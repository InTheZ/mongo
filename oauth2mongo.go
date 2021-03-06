package oauth2mongo

import (
	"context"
	"encoding/json"
	"github.com/mongodb/mongo-go-driver/bson/objectid"
	"time"

	"github.com/mongodb/mongo-go-driver/bson"
	"github.com/mongodb/mongo-go-driver/mongo"
	"github.com/mongodb/mongo-go-driver/x/bsonx"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
	"log"
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

// CreateIndex create a new index based on an IndexModel
func CreateIndex(client *mongo.Client, dbName string, collectionName string, index *mongo.IndexModel) {
	indexView := client.Database(dbName).Collection(collectionName).Indexes()
	_, err := indexView.CreateOne(context.Background(), *index)
	if err != nil {
		log.Fatal(err)
	}
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

	CreateIndex(client, dbName, ts.tcfg.BasicCName, &mongo.IndexModel{
		Keys: bsonx.Doc{{"ExpiredAt", bsonx.Int32(1)}},
		Options: mongo.NewIndexOptionsBuilder().
			ExpireAfterSeconds(1).
			Name("basicCNameIndex").
			Build(),
	})

	CreateIndex(client, dbName, ts.tcfg.AccessCName, &mongo.IndexModel{
		Keys: bsonx.Doc{{"ExpiredAt", bsonx.Int32(1)}},
		Options: mongo.NewIndexOptionsBuilder().
			ExpireAfterSeconds(1).
			Name("accessCNameIndex").
			Build(),
	})

	CreateIndex(client, dbName, ts.tcfg.RefreshCName, &mongo.IndexModel{
		Keys: bsonx.Doc{{"ExpiredAt", bsonx.Int32(1)}},
		Options: mongo.NewIndexOptionsBuilder().
			ExpireAfterSeconds(1).
			Name("refreshCNameIndex").
			Build(),
	})

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

// InsertOne inserts a document into the database
func InsertOne(ts *TokenStore, collectionName string, doc *bson.D) (err error) {
	_, verr := ts.client.Database(ts.dbName).Collection(collectionName).InsertOne(context.Background(), doc)
	if verr != nil {
		log.Fatal(verr)
		err = verr
		return
	}
	return
}

// Create create and store the new token information
func (ts *TokenStore) Create(info oauth2.TokenInfo) (err error) {
	jv, err := json.Marshal(info)
	if err != nil {
		return
	}

	if code := info.GetCode(); code != "" {
		InsertOne(ts, ts.tcfg.BasicCName,
			&bson.D{
				{"_id", code},
				{"Data", string(jv[:])},
				{"ExpiredAt", time.Unix(0, info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()).
					UnixNano()/int64(time.Millisecond))},
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
	id := objectid.New().Hex()

	InsertOne(ts, ts.tcfg.BasicCName,
		&bson.D{
			{"_id", id},
			{"Data", string(jv[:])},
			{"ExpiredAt", time.Unix(0, rexp.UnixNano()/int64(time.Millisecond))},
		})

	if info.GetAccess() != "" {
		InsertOne(ts, ts.tcfg.AccessCName,
			&bson.D{
				{"_id", info.GetAccess()},
				{"BasicID", id},
				{"ExpiredAt", time.Unix(0, aexp.UnixNano()/int64(time.Millisecond))},
			})
	}

	if refresh := info.GetRefresh(); refresh != "" {
		InsertOne(ts, ts.tcfg.RefreshCName,
			&bson.D{
				{"_id", refresh},
				{"BasicID", id},
				{"ExpiredAt", time.Unix(0, rexp.UnixNano()/int64(time.Millisecond))},
			})
	}
	return
}

// DeleteByID deletes a document by the _id value
func DeleteByID(ts *TokenStore, collectionName string, id string) (err error) {
	_, verr := ts.client.Database(ts.dbName).Collection(collectionName).DeleteOne(context.Background(),
		bson.M{
			"_id": id,
		})
	if verr != nil {
		err = verr
		return
	}
	return
}

// RemoveByCode use the authorization code to delete the token information
func (ts *TokenStore) RemoveByCode(code string) (err error) {
	verr := DeleteByID(ts, ts.tcfg.BasicCName, code)
	if verr != nil {
		err = verr
		return
	}
	return
}

// RemoveByAccess use the access token to delete the token information
func (ts *TokenStore) RemoveByAccess(access string) (err error) {
	verr := DeleteByID(ts, ts.tcfg.AccessCName, access)
	if verr != nil {
		err = verr
		return
	}
	return
}

// RemoveByRefresh use the refresh token to delete the token information
func (ts *TokenStore) RemoveByRefresh(refresh string) (err error) {
	verr := DeleteByID(ts, ts.tcfg.RefreshCName, refresh)
	if verr != nil {
		err = verr
		return
	}
	return
}

// FindByID returns a DocumentResult for a given ID
func FindByID(ts *TokenStore, collectionName string, id string) (doc *mongo.DocumentResult) {
	doc = ts.client.Database(ts.dbName).Collection(collectionName).FindOne(context.Background(), bson.M{"_id": id})
	return
}

func (ts *TokenStore) getData(basicID string) (ti oauth2.TokenInfo, err error) {
	var bd basicData
	verr := FindByID(ts, ts.tcfg.BasicCName, basicID).Decode(&bd)
	if verr != nil {
		if verr == mongo.ErrNoDocuments {
			return
		}
		log.Fatal(verr)
		err = verr
		return
	}
	var tm models.Token
	err = json.Unmarshal([]byte(bd.Data), &tm)
	if err != nil {
		return
	}
	ti = &tm
	return
}

func (ts *TokenStore) getBasicID(cname, token string) (basicID string, err error) {
	var td tokenData
	verr := FindByID(ts, cname, token).Decode(&td)
	if verr != nil {
		if verr == mongo.ErrNoDocuments {
			return
		}
		err = verr
		return
	}
	basicID = td.BasicID
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
	Data      string    `bson:"Data"`
	ExpiredAt time.Time `bson:"ExpiredAt"`
}

type tokenData struct {
	ID        string    `bson:"_id"`
	BasicID   string    `bson:"BasicID"`
	ExpiredAt time.Time `bson:"ExpiredAt"`
}
