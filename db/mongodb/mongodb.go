package mongodb

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/prometheus/common/log"
	"github.com/sqwatch-demo/user/users"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/url"
	"os"
)

var (
	name     string
	password string
	host     string
	mongoUri string
	db       = "users"
	//ErrInvalidHexID represents a entity id that is not a valid bson ObjectID
	ErrInvalidHexID = errors.New("Invalid Id Hex")
)

func init() {
	flag.StringVar(&name, "mongo-user", os.Getenv("MONGO_USER"), "Mongo user")
	flag.StringVar(&password, "mongo-password", os.Getenv("MONGO_PASS"), "Mongo password")
	flag.StringVar(&host, "mongo-host", os.Getenv("MONGO_HOST"), "Mongo host")
	flag.StringVar(&mongoUri, "mongo-uri", os.Getenv("MONGODB_URI"), "Mongo uri")
}

func newDBClient(ctx context.Context) (*mongo.Client, error) {
	return mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoUri))
}

// Mongo meets the Database interface requirements
type Mongo struct {
	//Session is a MongoDB Session
	Client  *mongo.Client
	Session *mongo.Session
}

// Init MongoDB
func (m *Mongo) Init() error {
	log.Infof("initializing mongo db: name(%s) passwd(%s) host(%s)", name, password, host)
	u := getURL()
	log.Infof("initializing mongo db: url(%s)", u.String())
	var err error
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	if err = m.Ping(); err != nil {
		log.Errorf("mongo ping() err: %v", err)
		return err
	}
	if err = m.EnsureIndexes(); err != nil {
		log.Errorf("mongo EnsureIndexes() error: %v", err)
		return err
	}
	return nil
}

// MongoUser is a wrapper for the users
type MongoUser struct {
	users.User `bson:",inline"`
	ID         primitive.ObjectID   `json:"_id" bson:"_id"`
	AddressIDs []primitive.ObjectID `bson:"addresses"`
	CardIDs    []primitive.ObjectID `bson:"cards"`
}

// New Returns a new MongoUser
func New() MongoUser {
	u := users.New()
	return MongoUser{
		User:       u,
		AddressIDs: make([]primitive.ObjectID, 0),
		CardIDs:    make([]primitive.ObjectID, 0),
	}
}

// AddUserIDs adds userID as string to user
func (mu *MongoUser) AddUserIDs() {
	if mu.User.Addresses == nil {
		mu.User.Addresses = make([]users.Address, 0)
	}
	for _, id := range mu.AddressIDs {
		mu.User.Addresses = append(mu.User.Addresses, users.Address{
			ID: id.Hex(),
		})
	}
	if mu.User.Cards == nil {
		mu.User.Cards = make([]users.Card, 0)
	}
	for _, id := range mu.CardIDs {
		mu.User.Cards = append(mu.User.Cards, users.Card{ID: id.Hex()})
	}
	mu.User.UserID = mu.ID.Hex()
}

// MongoAddress is a wrapper for Address
type MongoAddress struct {
	users.Address `bson:",inline"`
	ID            primitive.ObjectID `json:"_id" bson:"_id"`
}

// AddID ObjectID as string
func (m *MongoAddress) AddID() {
	m.Address.ID = m.ID.Hex()
}

// MongoCard is a wrapper for Card
type MongoCard struct {
	users.Card `bson:",inline"`
	ID         primitive.ObjectID `json:"_id" bson:"_id"`
}

// AddID ObjectID as string
func (m *MongoCard) AddID() {
	m.Card.ID = m.ID.Hex()
}

// CreateUser Insert user to MongoDB, including connected addresses and cards, update passed in user with Ids
func (m *Mongo) CreateUser(u *users.User) error {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	mu := New()
	mu.User = *u
	id := primitive.NewObjectID()
	mu.ID = id
	var carderr error
	var addrerr error
	mu.CardIDs, carderr = m.createCards(u.Cards)
	mu.AddressIDs, addrerr = m.createAddresses(u.Addresses)
	c := client.Database(db).Collection("customers")
	_, err = c.InsertOne(context.TODO(), mu)
	if err != nil {
		// Gonna clean up if we can, ignore error
		// because the user save error takes precedence.
		m.cleanAttributes(mu)
		return err
	}
	mu.User.UserID = mu.UserID
	// Cheap err for attributes
	if carderr != nil || addrerr != nil {
		return fmt.Errorf("%v %v", carderr, addrerr)
	}
	*u = mu.User
	return nil
}

func (m *Mongo) createCards(cs []users.Card) ([]primitive.ObjectID, error) {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	ids := make([]primitive.ObjectID, 0)
	for k, ca := range cs {
		id := primitive.NewObjectID()
		mc := MongoCard{Card: ca, ID: id}
		c := client.Database(db).Collection("cards")
		_, err = c.InsertOne(ctx, mc)
		if err != nil {
			return ids, err
		}
		ids = append(ids, id)
		cs[k].ID = id.Hex()
	}
	return ids, nil
}

func (m *Mongo) createAddresses(as []users.Address) ([]primitive.ObjectID, error) {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	ids := make([]primitive.ObjectID, 0)
	for k, a := range as {
		id := primitive.NewObjectID()
		ma := MongoAddress{Address: a, ID: id}
		c := client.Database(db).Collection("addresses")
		_, err = c.InsertOne(ctx, ma)
		if err != nil {
			return ids, err
		}
		ids = append(ids, id)
		as[k].ID = id.Hex()
	}
	return ids, nil
}

func (m *Mongo) cleanAttributes(mu MongoUser) error {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("addresses")
	_, err = c.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": mu.AddressIDs}})
	if err != nil {
		return fmt.Errorf("cannot delete addresses: a(%+v) err(%v)", mu.AddressIDs, err)
	}
	c = client.Database(db).Collection("cards")
	_, err = c.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": mu.CardIDs}})
	if err != nil {
		return fmt.Errorf("cannot delete cards: c(%+v) err(%v)", mu.CardIDs, err)
	}
	return err
}

func (m *Mongo) appendAttributeId(attr string, id primitive.ObjectID, userid string) error {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("customers")
	uid, err := primitive.ObjectIDFromHex(userid)
	if err != nil {
		return err
	}
	_, err = c.UpdateByID(ctx, bson.M{"_id": uid},
		bson.M{"$addToSet": bson.M{attr: id}})
	return err
}

func (m *Mongo) removeAttributeId(attr string, id primitive.ObjectID, userid string) error {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("customers")
	uid, err := primitive.ObjectIDFromHex(userid)
	if err != nil {
		return err
	}
	_, err = c.UpdateByID(ctx, bson.M{"_id": uid},
		bson.M{"$pull": bson.M{attr: id}})
	if err != nil {
		return err
	}
	return nil
}

// GetUserByName Get user by their name
func (m *Mongo) GetUserByName(name string) (users.User, error) {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return users.User{}, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("customers")
	mu := New()
	err = c.FindOne(ctx, bson.M{"username": name}).Decode(&mu)
	mu.AddUserIDs()
	return mu.User, err
}

// GetUser Get user by their object id
func (m *Mongo) GetUser(id string) (users.User, error) {
	if !primitive.IsValidObjectID(id) {
		return users.New(), errors.New("Invalid Id Hex")
	}
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return users.User{}, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("customers")
	mu := New()
	uid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return users.User{}, err
	}
	err = c.FindOne(ctx, bson.M{"_id": uid}).Decode(&mu)
	mu.AddUserIDs()
	return mu.User, err
}

// GetUsers Get all users
func (m *Mongo) GetUsers() ([]users.User, error) {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("customers")
	var mus []MongoUser
	cur, err := c.Find(ctx, nil) //.All(&mus)
	if err != nil {
		return nil, err
	}
	if err = cur.All(ctx, &mus); err != nil {
		return nil, err
	}
	us := make([]users.User, 0)
	for _, mu := range mus {
		mu.AddUserIDs()
		us = append(us, mu.User)
	}
	return us, err
}

// GetUserAttributes given a user, load all cards and addresses connected to that user
func (m *Mongo) GetUserAttributes(u *users.User) error {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)

	ids := make([]primitive.ObjectID, 0)
	for _, a := range u.Addresses {
		if !primitive.IsValidObjectID(a.ID) {
			return ErrInvalidHexID
		}
		oid, err := primitive.ObjectIDFromHex(a.ID)
		if err != nil {
			return ErrInvalidHexID
		}
		ids = append(ids, oid)
	}
	var ma []MongoAddress
	c := client.Database(db).Collection("addresses")
	cur, err := c.Find(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return err
	}
	if err = cur.All(ctx, &ma); err != nil {
		return err
	}
	na := make([]users.Address, 0)
	for _, a := range ma {
		a.Address.ID = a.ID.Hex()
		na = append(na, a.Address)
	}
	u.Addresses = na

	ids = make([]primitive.ObjectID, 0)
	for _, c := range u.Cards {
		if !primitive.IsValidObjectID(c.ID) {
			return ErrInvalidHexID
		}
		oid, err := primitive.ObjectIDFromHex(c.ID)
		if err != nil {
			return err
		}
		ids = append(ids, oid)
	}
	var mc []MongoCard
	c = client.Database(db).Collection("cards")
	cur, err = c.Find(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return err
	}

	if err = cur.All(ctx, &mc); err != nil {
		return err
	}

	nc := make([]users.Card, 0)
	for _, ca := range mc {
		ca.Card.ID = ca.ID.Hex()
		nc = append(nc, ca.Card)
	}
	u.Cards = nc
	return nil
}

// GetCard Gets card by objects Id
func (m *Mongo) GetCard(id string) (users.Card, error) {
	if !primitive.IsValidObjectID(id) {
		return users.Card{}, errors.New("Invalid Id Hex")
	}
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return users.Card{}, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("cards")
	mc := MongoCard{}
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return users.Card{}, err
	}
	err = c.FindOne(ctx, oid).Decode(&mc)
	if err != nil {
		return users.Card{}, err
	}
	mc.AddID()
	return mc.Card, err
}

// GetCards Gets all cards
func (m *Mongo) GetCards() ([]users.Card, error) {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("cards")
	var mcs []MongoCard
	cur, err := c.Find(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = cur.All(ctx, &mcs); err != nil {
		return nil, err
	}
	cs := make([]users.Card, 0)
	for _, mc := range mcs {
		mc.AddID()
		cs = append(cs, mc.Card)
	}
	return cs, err
}

// CreateCard adds card to MongoDB
func (m *Mongo) CreateCard(ca *users.Card, userid string) error {
	if userid != "" && !primitive.IsValidObjectID(userid) {
		return errors.New("Invalid Id Hex")
	}
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("cards")
	id := primitive.NewObjectID()
	mc := MongoCard{Card: *ca, ID: id}
	_, err = c.InsertOne(ctx, mc)
	if err != nil {
		return err
	}
	// Address for anonymous user
	if userid != "" {
		err = m.appendAttributeId("cards", mc.ID, userid)
		if err != nil {
			return err
		}
	}
	mc.AddID()
	*ca = mc.Card
	return err
}

// GetAddress Gets an address by object Id
func (m *Mongo) GetAddress(id string) (users.Address, error) {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return users.Address{}, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("addresses")
	ma := MongoAddress{}
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return users.Address{}, err
	}
	err = c.FindOne(ctx, oid).Decode(&ma)
	ma.AddID()
	return ma.Address, err
}

// GetAddresses gets all addresses
func (m *Mongo) GetAddresses() ([]users.Address, error) {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("addresses")
	var mas []MongoAddress
	cur, err := c.Find(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = cur.All(ctx, &mas); err != nil {
		return nil, err
	}
	as := make([]users.Address, 0)
	for _, ma := range mas {
		ma.AddID()
		as = append(as, ma.Address)
	}
	return as, err
}

// CreateAddress Inserts Address into MongoDB
func (m *Mongo) CreateAddress(a *users.Address, userid string) error {
	if userid != "" && !primitive.IsValidObjectID(userid) {
		return errors.New("Invalid Id Hex")
	}
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection("addresses")
	id := primitive.NewObjectID()
	ma := MongoAddress{Address: *a, ID: id}
	_, err = c.InsertOne(ctx, ma)
	if err != nil {
		return err
	}
	// Address for anonymous user
	if userid != "" {
		err = m.appendAttributeId("addresses", ma.ID, userid)
		if err != nil {
			return err
		}
	}
	ma.AddID()
	*a = ma.Address
	return err
}

// CreateAddress Inserts Address into MongoDB
func (m *Mongo) Delete(entity, id string) error {
	if !primitive.IsValidObjectID(id) {
		return errors.New("Invalid Id Hex")
	}
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	c := client.Database(db).Collection(entity)
	if entity == "customers" {
		u, err := m.GetUser(id)
		if err != nil {
			return err
		}
		aids := make([]primitive.ObjectID, 0)
		for _, a := range u.Addresses {
			oid, err := primitive.ObjectIDFromHex(a.ID)
			if err != nil {
				return err
			}
			aids = append(aids, oid)
		}
		cids := make([]primitive.ObjectID, 0)
		for _, c := range u.Cards {
			oid, err := primitive.ObjectIDFromHex(c.ID)
			if err != nil {
				return err
			}
			cids = append(cids, oid)
		}
		ac := client.Database(db).Collection("addresses")
		if _, err = ac.DeleteOne(ctx, bson.M{"_id": bson.M{"$in": aids}}); err != nil {
			return err
		}
		cc := client.Database(db).Collection("cards")
		if _, err = cc.DeleteOne(ctx, bson.M{"_id": bson.M{"$in": cids}}); err != nil {
			return err
		}
	} else {
		c := client.Database(db).Collection("customers")
		oid, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return err
		}
		c.UpdateMany(ctx, bson.M{}, bson.M{"$pull": bson.M{entity: oid}})
	}
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	_, err = c.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

func getURL() url.URL {
	ur := url.URL{
		Scheme: "mongodb",
		Host:   host,
	}
	if name != "" {
		u := url.UserPassword(name, password)
		ur.User = u
	}
	return ur
}

// EnsureIndexes ensures username is unique
func (m *Mongo) EnsureIndexes() error {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	i := mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true).SetSparse(true),
	}
	c := client.Database(db).Collection("customers")
	_, err = c.Indexes().CreateOne(ctx, i)
	return err
}

func (m *Mongo) Ping() error {
	ctx := context.TODO()
	client, err := newDBClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot create mongodb client: %v", err)
	}
	defer client.Disconnect(ctx)
	return client.Ping(ctx, nil)
}
