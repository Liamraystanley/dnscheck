package main

import (
	"bytes"
	"encoding/gob"
	"log"
	"time"

	"github.com/boltdb/bolt"
)

// DB allows us to embed the bolt db so we can implement custom methods upon it
type DB struct {
	*bolt.DB
}

var defaultBuckets = []string{"records"}

// newDB returns a new DB object. If there are no errors, db.Clean() should ALWAYS be ran
// to clean up and close the database.
func newDB() (*DB, error) {
	boltdb, err := bolt.Open(conf.Database, 0600, &bolt.Options{Timeout: 5 * time.Second})

	if err != nil {
		return nil, err
	}

	db := &DB{boltdb}

	return db, nil
}

// initDatabase initializes the needed structure of the database, so these checks don't
// have to be completed for every query (e.g. if a bucket is created).
// One would assume a bucket is not removed while the bot is running.
func initDatabase() {
	db, err := newDB()
	if err != nil {
		logger.Fatal("unable to instantiate database:", err)
	}
	defer db.Clean()

	for _, bucket := range defaultBuckets {
		if err := db.VerifyBucket(bucket); err != nil {
			logger.Fatalf("unable to create/access bucket %s: %s", bucket, err)
		}
	}

	return
}

// Clean is a wrapper around db.Close() that runs regardless of error.
func (db *DB) Clean() {
	_ = db.Close()

	return
}

// VerifyBucket is used to verify that a bucket exists and that the database is readable.
func (db *DB) VerifyBucket(bucket string) error {
	return db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))

		return err
	})
}

// Count returns the number of keys in name
func (db *DB) Count(name string) (stats int, err error) {
	if err = db.VerifyBucket(name); err != nil {
		return stats, err
	}

	err = db.View(func(tx *bolt.Tx) error {
		stats = tx.Bucket([]byte(name)).Stats().KeyN

		return nil
	})

	return stats, err
}

// SetStruct sets data{} into bytes(key) on bytes(bucket)
func (db *DB) SetStruct(bucket, key string, data interface{}) error {
	if err := db.VerifyBucket(bucket); err != nil {
		return err
	}

	return db.Update(func(tx *bolt.Tx) error {
		buffer := new(bytes.Buffer)
		encoder := gob.NewEncoder(buffer)

		if err := encoder.Encode(data); err != nil {
			log.Println("encode:", err)
			return err
		}

		return tx.Bucket([]byte(bucket)).Put([]byte(key), buffer.Bytes())
	})
}

// GetStruct gets bytes from bytes(key) on bytes(bucket) and sets into &input{}
func (db *DB) GetStruct(bucket, key string, input interface{}) error {
	if err := db.VerifyBucket(bucket); err != nil {
		return err
	}

	return db.View(func(tx *bolt.Tx) error {
		return gob.NewDecoder(bytes.NewBuffer(tx.Bucket([]byte(bucket)).Get([]byte(key)))).Decode(input)
	})
}

// GetReceivedStruct takes bytes (e.g. from iterating over db) and sets into &input{}
func (db *DB) GetReceivedStruct(data []byte, input interface{}) error {
	return gob.NewDecoder(bytes.NewBuffer(data)).Decode(input)
}

// Set sets string(data) into bytes(key) on bytes(bucket)
func (db *DB) Set(bucket, key string, data string) error {
	if err := db.VerifyBucket(bucket); err != nil {
		return err
	}

	return db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucket)).Put([]byte(key), []byte(data))
	})
}

// Get gets type(string) from bytes(key) on bytes(bucket)
func (db *DB) Get(bucket, key string) (out string, err error) {
	if err = db.VerifyBucket(bucket); err != nil {
		return "", err
	}

	err = db.View(func(tx *bolt.Tx) error {
		out = string(tx.Bucket([]byte(bucket)).Get([]byte(key))[:])

		return nil
	})

	return out, err
}
