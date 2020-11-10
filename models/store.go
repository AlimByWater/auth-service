package models

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	collection *mongo.Collection
	ctx        = context.TODO()
	client     *mongo.Client
)

func GetCollection(ctx context.Context) (*mongo.Client, *mongo.Collection) {
	clientOptions := options.Client().ApplyURI("mongodb+srv://arimaAdmin:medods@medods.3nstz.mongodb.net/authService?retryWrites=true&w=majority")
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	collection = client.Database("authService").Collection("users")

	return client, collection
}

func GetContext() context.Context {
	return ctx
}

func Disconnect() {
	client.Disconnect(ctx)
}
