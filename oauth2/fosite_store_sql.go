/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package oauth2

import (
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/sirupsen/logrus"

	"github.com/ory/fosite"
	"github.com/ory/go-convenience/stringsx"
	"github.com/ory/hydra/client"
	"github.com/ory/x/dbal"
	"github.com/ory/x/sqlcon"
)

type FositeSQLStore struct {
	client.Manager
	DB                  *sqlx.DB
	L                   logrus.FieldLogger
	AccessTokenLifespan time.Duration
	HashSignature       bool
}

func NewFositeSQLStore(m client.Manager,
	db *sqlx.DB,
	l logrus.FieldLogger,
	accessTokenLifespan time.Duration,
	hashSignature bool,
) *FositeSQLStore {
	return &FositeSQLStore{
		Manager:             m,
		L:                   l,
		DB:                  db,
		AccessTokenLifespan: accessTokenLifespan,
		HashSignature:       hashSignature,
	}
}

const (
	sqlTableOpenID  = "oidc"
	sqlTableAccess  = "access"
	sqlTableRefresh = "refresh"
	sqlTableCode    = "code"
	sqlTablePKCE    = "pkce"
)

type contextKey string
var transactionKey = contextKey("transaction")

var Migrations = map[string]*dbal.PackrMigrationSource{
	dbal.DriverMySQL: dbal.NewMustPackerMigrationSource(logrus.New(), AssetNames(), Asset, []string{
		"migrations/sql/shared",
		"migrations/sql/mysql",
	}, true),
	dbal.DriverPostgreSQL: dbal.NewMustPackerMigrationSource(logrus.New(), AssetNames(), Asset, []string{
		"migrations/sql/shared",
		"migrations/sql/postgres",
	}, true),
}

var sqlParams = []string{
	"signature",
	"request_id",
	"requested_at",
	"client_id",
	"scope",
	"granted_scope",
	"form_data",
	"session_data",
	"subject",
	"active",
	"requested_audience",
	"granted_audience",
	"challenge_id",
}

type sqlData struct {
	PK                int            `db:"pk"`
	Signature         string         `db:"signature"`
	Request           string         `db:"request_id"`
	ConsentChallenge  sql.NullString `db:"challenge_id"`
	RequestedAt       time.Time      `db:"requested_at"`
	Client            string         `db:"client_id"`
	Scopes            string         `db:"scope"`
	GrantedScope      string         `db:"granted_scope"`
	RequestedAudience string         `db:"requested_audience"`
	GrantedAudience   string         `db:"granted_audience"`
	Form              string         `db:"form_data"`
	Subject           string         `db:"subject"`
	Active            bool           `db:"active"`
	Session           []byte         `db:"session_data"`
}

func sqlSchemaFromRequest(signature string, r fosite.Requester, logger logrus.FieldLogger) (*sqlData, error) {
	subject := ""
	if r.GetSession() == nil {
		logger.Debugf("Got an empty session in sqlSchemaFromRequest")
	} else {
		subject = r.GetSession().GetSubject()
	}

	session, err := json.Marshal(r.GetSession())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var challenge sql.NullString
	rr, ok := r.GetSession().(*Session)
	if !ok && r.GetSession() != nil {
		return nil, errors.Errorf("Expected request to be of type *Session, but got: %T", r.GetSession())
	} else if ok {
		if len(rr.ConsentChallenge) > 0 {
			challenge = sql.NullString{Valid: true, String: rr.ConsentChallenge}
		}
	}

	return &sqlData{
		Request:           r.GetID(),
		ConsentChallenge:  challenge,
		Signature:         signature,
		RequestedAt:       r.GetRequestedAt(),
		Client:            r.GetClient().GetID(),
		Scopes:            strings.Join([]string(r.GetRequestedScopes()), "|"),
		GrantedScope:      strings.Join([]string(r.GetGrantedScopes()), "|"),
		GrantedAudience:   strings.Join([]string(r.GetGrantedAudience()), "|"),
		RequestedAudience: strings.Join([]string(r.GetRequestedAudience()), "|"),
		Form:              r.GetRequestForm().Encode(),
		Session:           session,
		Subject:           subject,
		Active:            true,
	}, nil
}

func (s *sqlData) toRequest(session fosite.Session, cm client.Manager, logger logrus.FieldLogger) (*fosite.Request, error) {
	if session != nil {
		if err := json.Unmarshal(s.Session, session); err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		logger.Debugf("Got an empty session in toRequest")
	}

	c, err := cm.GetClient(context.Background(), s.Client)
	if err != nil {
		return nil, err
	}

	val, err := url.ParseQuery(s.Form)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := &fosite.Request{
		ID:                s.Request,
		RequestedAt:       s.RequestedAt,
		Client:            c,
		RequestedScope:    fosite.Arguments(stringsx.Splitx(s.Scopes, "|")),
		GrantedScope:      fosite.Arguments(stringsx.Splitx(s.GrantedScope, "|")),
		RequestedAudience: fosite.Arguments(stringsx.Splitx(s.RequestedAudience, "|")),
		GrantedAudience:   fosite.Arguments(stringsx.Splitx(s.GrantedAudience, "|")),
		Form:              val,
		Session:           session,
	}

	return r, nil
}

// hashSignature prevents errors where the signature is longer than 128 characters (and thus doesn't fit into the pk).
func (s *FositeSQLStore) hashSignature(signature, table string) string {
	if table == sqlTableAccess && s.HashSignature {
		return fmt.Sprintf("%x", sha512.Sum384([]byte(signature)))
	}
	return signature
}

func (s *FositeSQLStore) createSession(ctx context.Context, signature string, requester fosite.Requester, table string) error {
	signature = s.hashSignature(signature, table)
	op := s.operator(ctx)

	data, err := sqlSchemaFromRequest(signature, requester, s.L)
	if err != nil {
		return err
	}

	query := fmt.Sprintf(
		"INSERT INTO hydra_oauth2_%s (%s) VALUES (%s)",
		table,
		strings.Join(sqlParams, ", "),
		":"+strings.Join(sqlParams, ", :"),
	)
	if _, err := op.NamedExecContext(ctx, query, data); err != nil {
		return sqlcon.HandleError(err)
	}
	return nil
}

func (s *FositeSQLStore) findSessionBySignature(ctx context.Context, signature string, session fosite.Session, table string) (fosite.Requester, error) {
	signature = s.hashSignature(signature, table)
	op := s.operator(ctx)

	var d sqlData
	if err := op.GetContext(ctx, &d, op.Rebind(fmt.Sprintf("SELECT * FROM hydra_oauth2_%s WHERE signature=?", table)), signature); err == sql.ErrNoRows {
		return nil, errors.Wrap(fosite.ErrNotFound, "")
	} else if err != nil {
		return nil, sqlcon.HandleError(err)
	} else if !d.Active && table == sqlTableCode {
		if r, err := d.toRequest(session, s.Manager, s.L); err != nil {
			return nil, err
		} else {
			return r, errors.WithStack(fosite.ErrInvalidatedAuthorizeCode)
		}
	} else if !d.Active {
		return nil, errors.WithStack(fosite.ErrInactiveToken)
	}

	return d.toRequest(session, s.Manager, s.L)
}

func (s *FositeSQLStore) deleteSession(ctx context.Context, signature string, table string) error {
	op := s.operator(ctx)
	signature = s.hashSignature(signature, table)

	if _, err := op.ExecContext(ctx, op.Rebind(fmt.Sprintf("DELETE FROM hydra_oauth2_%s WHERE signature=?", table)), signature); err != nil {
		return sqlcon.HandleError(err)
	}
	return nil
}

func (s *FositeSQLStore) CreateSchemas() (int, error) {
	migrate.SetTable("hydra_oauth2_migration")
	n, err := migrate.Exec(s.DB.DB, s.DB.DriverName(), Migrations[dbal.Canonicalize(s.DB.DriverName())], migrate.Up)
	if err != nil {
		return 0, errors.Wrapf(err, "Could not migrate sql schema, applied %d migrations", n)
	}
	return n, nil
}

func (s *FositeSQLStore) CreateOpenIDConnectSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(ctx, signature, requester, sqlTableOpenID)
}

func (s *FositeSQLStore) GetOpenIDConnectSession(ctx context.Context, signature string, requester fosite.Requester) (fosite.Requester, error) {
	return s.findSessionBySignature(ctx, signature, requester.GetSession(), sqlTableOpenID)
}

func (s *FositeSQLStore) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature, sqlTableOpenID)
}

func (s *FositeSQLStore) CreateAuthorizeCodeSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(ctx, signature, requester, sqlTableCode)
}

func (s *FositeSQLStore) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(ctx, signature, session, sqlTableCode)
}

func (s *FositeSQLStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	op := s.operator(ctx)
	if _, err := op.ExecContext(ctx, op.Rebind(fmt.Sprintf(
		"UPDATE hydra_oauth2_%s SET active=false WHERE signature=?",
		sqlTableCode,
	)), signature); err != nil {
		return sqlcon.HandleError(err)
	}

	return nil
}

func (s *FositeSQLStore) CreateAccessTokenSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(ctx, signature, requester, sqlTableAccess)
}

func (s *FositeSQLStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(ctx, signature, session, sqlTableAccess)
}

func (s *FositeSQLStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature, sqlTableAccess)
}

func (s *FositeSQLStore) CreateRefreshTokenSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(ctx, signature, requester, sqlTableRefresh)
}

func (s *FositeSQLStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(ctx, signature, session, sqlTableRefresh)
}

func (s *FositeSQLStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature, sqlTableRefresh)
}

func (s *FositeSQLStore) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(ctx, signature, requester, sqlTablePKCE)
}

func (s *FositeSQLStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(ctx, signature, session, sqlTablePKCE)
}

func (s *FositeSQLStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.deleteSession(ctx, signature, sqlTablePKCE)
}

func (s *FositeSQLStore) CreateImplicitAccessTokenSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.CreateAccessTokenSession(ctx, signature, requester)
}

func (s *FositeSQLStore) RevokeRefreshToken(ctx context.Context, id string) error {
	return s.revokeSession(ctx, id, sqlTableRefresh)
}

func (s *FositeSQLStore) RevokeAccessToken(ctx context.Context, id string) error {
	return s.revokeSession(ctx, id, sqlTableAccess)
}

func (s *FositeSQLStore) revokeSession(ctx context.Context, id string, table string) error {
	op := s.operator(ctx)
	if _, err := op.ExecContext(ctx, op.Rebind(fmt.Sprintf("DELETE FROM hydra_oauth2_%s WHERE request_id=?", table)), id); err == sql.ErrNoRows {
		return errors.Wrap(fosite.ErrNotFound, "")
	} else if err != nil {
		return sqlcon.HandleError(err)
	}
	return nil
}

func (s *FositeSQLStore) FlushInactiveAccessTokens(ctx context.Context, notAfter time.Time) error {
	if _, err := s.DB.ExecContext(ctx, s.DB.Rebind(fmt.Sprintf("DELETE FROM hydra_oauth2_%s WHERE requested_at < ? AND requested_at < ?", sqlTableAccess)), time.Now().Add(-s.AccessTokenLifespan), notAfter); err == sql.ErrNoRows {
		return errors.Wrap(fosite.ErrNotFound, "")
	} else if err != nil {
		return sqlcon.HandleError(err)
	}

	return nil
}

// internal convenience interface to keep storage methods DRY otherwise there will be hella lot of copy-pasta
// note sure if this is the best way to go about this tho ¯\_(ツ)_/¯
type operatorExtContext interface {
	sqlx.ExtContext
	GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	NamedExecContext(ctx context.Context, query string, arg interface{}) (sql.Result, error)
}

// helper used to determine whether we are dealing with a transaction or not. name is kinda shitty?
func (s *FositeSQLStore) operator(ctx context.Context) (operatorExtContext) {
	if txn, ok := ctx.Value(transactionKey).(*sqlx.Tx); ok {
		s.L.Infof("AMIR -------------------------- OPERATOR IS TXN - %+v", txn)
		return txn
	} else {
		return s.DB
	}
}

func (s *FositeSQLStore) BeginTX(ctx context.Context) (context.Context, error) {
	if txn, err := s.DB.BeginTxx(ctx, nil); err != nil {
		s.L.Errorf("AMIR -------------------------- BeginTX TRANSACTION ERROR: %+v", err)
		return ctx, err
	} else {
		s.L.Infof("AMIR -------------------------- BeginTX SUCCESS: %+v", txn)
		return context.WithValue(ctx, transactionKey, txn), nil
	}
}

func (s *FositeSQLStore) Commit(ctx context.Context) error {
	if txn, ok := ctx.Value(transactionKey).(*sqlx.Tx); ok {
		s.L.Infof("AMIR -------------------------- COMMITING TRANSACTION")
		return txn.Commit()
	} else {
		// TODO: probably don't want to panic here. Although it if this method is called by fosite
		// it's because you said you support transactions! So...are you lying?
		panic("no transaction available in context - wtf not cool man.")
	}
}

func (s *FositeSQLStore) Rollback(ctx context.Context) error {
	if txn, ok := ctx.Value(transactionKey).(*sqlx.Tx); ok {
		s.L.Infof("AMIR -------------------------- Rollback TRANSACTION")
		return txn.Rollback()
	} else {
		// TODO: probably don't want to panic here. Although it if this method is called by fosite
		// it's because you said you support transactions! So...are you lying?
		panic("no transaction available in context - wtf not cool man.")
	}
}