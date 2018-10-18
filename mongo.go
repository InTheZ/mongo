package mongo

import (
	"context"
	"encoding/json"
	"github.com/mongodb/mongo-go-driver/bson/objectid"
	"log"
	"time"

	"github.com/mongodb/mongo-go-driver/bson"
	"github.com/mongodb/mongo-go-driver/mongo"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
)

// Config mongodb configuration parameters
type Config struct {
	URL string
	DB  string
}

// NewConfig create mongodb configuration
func NewConfig(url, db string) *Config {
	return &Config{
		URL: url,
		DB:  db,
	}
}

// TokenConfig token configuration parameters
type TokenConfig struct {
	// store txn collection name(The default is oauth2)
	TxnCName string
	// store token based data collection name(The default is oauth2_basic)
	BasicCName string
	// store access token data collection name(The default is oauth2_access)
	AccessCName string
	// store refresh token data collection name(The default is oauth2_refresh)
	RefreshCName string
}

// NewDefaultTokenConfig create a default token configuration
func NewDefaultTokenConfig() *TokenConfig {
	return &TokenConfig{
		TxnCName:     "oauth2_txn",
		BasicCName:   "oauth2_basic",
		AccessCName:  "oauth2_access",
		RefreshCName: "oauth2_refresh",
	}
}

// NewTokenStore create a token store instance based on mongodb
func NewTokenStore(cfg *Config, tcfgs ...*TokenConfig) (store *TokenStore) {
	client, err := mongo.NewClient(cfg.URL)
	if err != nil {
		panic(err)
	}
	client.Connect(context.Background())

	return NewTokenStoreWithSession(client, cfg.DB, tcfgs...)
}

// NewTokenStoreWithSession create a token store instance based on mongodb
func NewTokenStoreWithSession(client *mongo.Client, dbName string, tcfgs ...*TokenConfig) (store *TokenStore) {
	ts := &TokenStore{
		dbName: dbName,
		client: client,
		tcfg:   NewDefaultTokenConfig(),
	}
	if len(tcfgs) > 0 {
		ts.tcfg = tcfgs[0]
	}

	indexViewBasicCName := client.Database(dbName).Collection(ts.tcfg.BasicCName).Indexes()

	_, err := indexViewBasicCName.CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys: bson.NewDocument(
				bson.EC.Int32("ExpiredAt", 1),
			),
			Options: mongo.NewIndexOptionsBuilder().
				ExpireAfterSeconds(1).
				Name("basicCNameIndex").
				Build(),
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	indexViewAccessCName := client.Database(dbName).Collection(ts.tcfg.AccessCName).Indexes()

	_, err = indexViewAccessCName.CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys: bson.NewDocument(
				bson.EC.Int32("ExpiredAt", 1),
			),
			Options: mongo.NewIndexOptionsBuilder().
				ExpireAfterSeconds(1).
				Name("accessCNameIndex").
				Build(),
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	indexViewRefreshCName := client.Database(dbName).Collection(ts.tcfg.RefreshCName).Indexes()

	_, err = indexViewRefreshCName.CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys: bson.NewDocument(
				bson.EC.Int32("ExpiredAt", 1),
			),
			Options: mongo.NewIndexOptionsBuilder().
				ExpireAfterSeconds(1).
				Name("refreshCNameIndex").
				Build(),
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	store = ts
	return
}

// TokenStore MongoDB storage for OAuth 2.0
type TokenStore struct {
	tcfg   *TokenConfig
	dbName string
	client *mongo.Client
}

// Close close the mongo session
func (ts *TokenStore) Close() {
	ts.client.Disconnect(context.Background())
}

func (ts *TokenStore) c(name string) *mongo.Collection {
	return ts.client.Database(ts.dbName).Collection(name)
}

func (ts *TokenStore) cHandler(name string, handler func(c *mongo.Collection)) {
	handler(ts.client.Database(ts.dbName).Collection(name))
	return
}

// Create create and store the new token information
func (ts *TokenStore) Create(info oauth2.TokenInfo) (err error) {
	jv, err := json.Marshal(info)
	if err != nil {
		return
	}

	if code := info.GetCode(); code != "" {
		ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) {
			_, verr := c.InsertOne(context.Background(),
				bson.NewDocument(
					bson.EC.String("_id", code),
					bson.EC.String("Data", string(jv[:])),
					bson.EC.DateTime("ExpiredAt", info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()).
						UnixNano()/int64(time.Millisecond)),
				),
			)
			if verr != nil {
				err = verr
				return
			}
			return
		})
	}

	aexp := info.GetAccessCreateAt().Add(info.GetAccessExpiresIn())
	rexp := aexp
	if refresh := info.GetRefresh(); refresh != "" {
		rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn())
		if aexp.Second() > rexp.Second() {
			aexp = rexp
		}
	}
	id := objectid.New()

	ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) {
		_, verr := c.InsertOne(context.Background(),
			bson.NewDocument(
				bson.EC.ObjectID("_id", id),
				bson.EC.String("Data", string(jv[:])),
				bson.EC.DateTime("ExpiredAt", rexp.UnixNano()/int64(time.Millisecond)),
			),
		)
		if verr != nil {
			err = verr
			return
		}
		return
	})

	ts.cHandler(ts.tcfg.AccessCName, func(c *mongo.Collection) {
		_, verr := c.InsertOne(context.Background(),
			bson.NewDocument(
				bson.EC.String("_id", info.GetAccess()),
				bson.EC.ObjectID("BasicID", id),
				bson.EC.DateTime("ExpiredAt", aexp.UnixNano()/int64(time.Millisecond)),
			),
		)
		if verr != nil {
			err = verr
			return
		}
		return
	})

	if refresh := info.GetRefresh(); refresh != "" {
		ts.cHandler(ts.tcfg.AccessCName, func(c *mongo.Collection) {
			_, verr := c.InsertOne(context.Background(),
				bson.NewDocument(
					bson.EC.String("_id", refresh),
					bson.EC.ObjectID("BasicID", id),
					bson.EC.DateTime("ExpiredAt", rexp.UnixNano()/int64(time.Millisecond)),
				),
			)
			if verr != nil {
				err = verr
				return
			}
			return
		})
	}
	return
}

// RemoveByCode use the authorization code to delete the token information
func (ts *TokenStore) RemoveByCode(code string) (err error) {
	ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) {
		_, verr := c.DeleteMany(context.Background(),
			bson.NewDocument(
				bson.EC.String("_id", code),
			))
		if verr != nil {
			err = verr
			return
		}
	})
	return
}

// RemoveByAccess use the access token to delete the token information
func (ts *TokenStore) RemoveByAccess(access string) (err error) {
	ts.cHandler(ts.tcfg.AccessCName, func(c *mongo.Collection) {
		_, verr := c.DeleteMany(context.Background(),
			bson.NewDocument(
				bson.EC.String("_id", access),
			))
		if verr != nil {
			err = verr
			return
		}
	})
	return
}

// RemoveByRefresh use the refresh token to delete the token information
func (ts *TokenStore) RemoveByRefresh(refresh string) (err error) {
	ts.cHandler(ts.tcfg.RefreshCName, func(c *mongo.Collection) {
		_, verr := c.DeleteMany(context.Background(),
			bson.NewDocument(
				bson.EC.String("_id", refresh),
			))
		if verr != nil {
			err = verr
			return
		}
	})
	return
}

func (ts *TokenStore) getData(basicID string) (ti oauth2.TokenInfo, err error) {
	ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) {
		var bd basicData
		verr := c.FindOne(context.Background(),
			bson.NewDocument(
				bson.EC.String("_id", basicID),
			)).Decode(&bd)
		if verr != nil {
			if verr == mongo.ErrNoDocuments {
				return
			}
			err = verr
			return
		}
		var tm models.Token
		err = json.Unmarshal(bd.Data, &tm)
		if err != nil {
			return
		}
		ti = &tm
	})
	return
}

func (ts *TokenStore) getBasicID(cname, token string) (basicID string, err error) {
	ts.cHandler(cname, func(c *mongo.Collection) {
		var td tokenData
		verr := c.FindOne(context.Background(),
			bson.NewDocument(
				bson.EC.String("_id", token),
			)).Decode(&td)
		if verr != nil {
			if verr == mongo.ErrNoDocuments {
				return
			}
			err = verr
			return
		}
		basicID = td.BasicID
	})
	return
}

// GetByCode use the authorization code for token information data
func (ts *TokenStore) GetByCode(code string) (ti oauth2.TokenInfo, err error) {
	ti, err = ts.getData(code)
	return
}

// GetByAccess use the access token for token information data
func (ts *TokenStore) GetByAccess(access string) (ti oauth2.TokenInfo, err error) {
	basicID, err := ts.getBasicID(ts.tcfg.AccessCName, access)
	if err != nil && basicID == "" {
		return
	}
	ti, err = ts.getData(basicID)
	return
}

// GetByRefresh use the refresh token for token information data
func (ts *TokenStore) GetByRefresh(refresh string) (ti oauth2.TokenInfo, err error) {
	basicID, err := ts.getBasicID(ts.tcfg.RefreshCName, refresh)
	if err != nil && basicID == "" {
		return
	}
	ti, err = ts.getData(basicID)
	return
}

type basicData struct {
	ID        string    `bson:"_id"`
	Data      []byte    `bson:"Data"`
	ExpiredAt time.Time `bson:"ExpiredAt"`
}

type tokenData struct {
	ID        string    `bson:"_id"`
	BasicID   string    `bson:"BasicID"`
	ExpiredAt time.Time `bson:"ExpiredAt"`
}
