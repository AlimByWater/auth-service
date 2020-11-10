package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/AlimByWater/auth-service/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

var (
	ctx                = models.GetContext()
	client, collection = models.GetCollection(ctx)
	SECRET_KEY         = "medods"
)

type User struct {
	ID            primitive.ObjectID `bson:"_id,omitempty"`
	Guid          string             `bson:"guid,omitempty"`
	Access_token  string             `bson:"aT,omitempty"`
	Refresh_token string             `bson:"rT,omitempty"`
	Exp           bool               `bson:"exp"`
}

type Request struct {
	Access_token  string `json:"access_token"`
	Refresh_token string `json:"refresh_token"`
}

func parseJson(body io.ReadCloser) (Request, error) {
	// taking pair of tokens from body
	tokenReq := Request{}
	err := json.NewDecoder(body).Decode(&tokenReq)
	if err != nil {
		return tokenReq, err
	}
	return tokenReq, nil
}

func tokenParse(Access_token string) (*jwt.Token, error) {
	token, err := jwt.Parse(Access_token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(SECRET_KEY), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func GenerateJWT(guid string) (map[string]string, error) {
	aToken := jwt.New(jwt.SigningMethodHS512)

	atClaims := aToken.Claims.(jwt.MapClaims)
	atClaims["sub"] = guid
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	accessToken, err := aToken.SignedString([]byte(SECRET_KEY))
	if err != nil {
		return nil, err
	}

	rToken := jwt.New(jwt.SigningMethodHS512)
	rtClaims := rToken.Claims.(jwt.MapClaims)
	rtClaims["sub"] = guid
	rtClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	refreshToken, err := rToken.SignedString([]byte(SECRET_KEY))
	if err != nil {
		return nil, err
	}

	//////////// converting refresh token to bcrypt hash ////////////
	hashedToken, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), 14)
	user := User{
		Guid:          guid,
		Access_token:  accessToken,
		Refresh_token: string(hashedToken),
		Exp:           false,
	}

	insertResult, err := collection.InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}

	fmt.Println("inserted", insertResult.InsertedID)

	return map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}, nil
}

func CreateToken(w http.ResponseWriter, r *http.Request) {
	guid := mux.Vars(r)["guid"]

	//////////// If not expired tokens already exists in db we just change their exp status to true ////////////
	update := bson.D{
		{"$set", bson.D{
			{"exp", true},
		}},
	}
	_, err := collection.UpdateMany(ctx, bson.D{{"guid", guid}, {"exp", false}}, update)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 400 status
		fmt.Fprintf(w, err.Error())
		return
	}

	validToken, err := GenerateJWT(guid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 400 status
		fmt.Fprintf(w, err.Error())
		return
	}

	// sending access and refresh tokens back
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{
		"access_token":  validToken["access_token"],
		"refresh_token": validToken["refresh_token"],
	}

	json.NewEncoder(w).Encode(resp)
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	tokenReq, err := parseJson(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, err.Error())
		return
	}

	token, err := tokenParse(tokenReq.Access_token)
	if err != nil || token == nil {
		w.WriteHeader(http.StatusInternalServerError) // 400 status
		return
	}

	// if token and claims are valid ...
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User

		filter := bson.D{
			{"aT", tokenReq.Access_token},
			{"exp", false},
		}
		err = collection.FindOne(ctx, filter).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError) // 400 status
			fmt.Fprintf(w, "Failed to find data in db: "+err.Error())
			return
		}

		if res := bcrypt.CompareHashAndPassword([]byte(user.Refresh_token), []byte(tokenReq.Refresh_token)); user.Exp == true || res != nil {
			w.WriteHeader(http.StatusUnauthorized) //401 status
			fmt.Fprintf(w, "Refres token expired or invalid")
			return
		}

		newTokenPair, err := GenerateJWT(claims["sub"].(string))
		if err != nil {
			fmt.Fprintf(w, err.Error())
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{
			"access_token":  newTokenPair["access_token"],
			"refresh_token": newTokenPair["refresh_token"],
		}
		json.NewEncoder(w).Encode(resp)

		//////////// Updating pair with old rT in db ////////////
		update := bson.D{
			{"$set", bson.D{
				{"exp", true},
			}},
		}
		_, err = collection.UpdateOne(ctx, filter, update)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError) // 400 status
			fmt.Fprintf(w, err.Error())
			return
		}

	} else if !token.Valid {
		filter := bson.D{
			{"aT", tokenReq.Access_token},
			{"exp", false},
		}
		update := bson.D{
			{"$set", bson.D{
				{"exp", true},
			}},
		}

		_, err = collection.UpdateOne(ctx, filter, update)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError) // 400 status
			fmt.Fprintf(w, err.Error())
			return
		}
	}
}

func RemoveToken(w http.ResponseWriter, r *http.Request) {
	tokenReq, err := parseJson(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 400 status
		fmt.Fprintf(w, err.Error())
		return
	}
	//////////// Check if access token is still valid ////////////
	token, err := tokenParse(tokenReq.Access_token)
	claims, ok := token.Claims.(jwt.MapClaims)
	if err != nil || token == nil || !ok {
		w.WriteHeader(http.StatusInternalServerError) // 400 status
		return
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized) // 401 status
		fmt.Fprintf(w, "Your access token is invalid")
		return
	}

	//////////// Finding this refresh token  ////////////
	var user User

	filterCursor, err := collection.Find(ctx, bson.D{{"guid", claims["sub"].(string)}})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, err.Error())
		return
	}
	ok = false
	for filterCursor.Next(ctx) {
		var tmp User
		if err = filterCursor.Decode(&tmp); err != nil {
			w.WriteHeader(http.StatusInternalServerError) // 400 status
			fmt.Fprintf(w, err.Error())
			return
		}
		// save matched document in User
		if err = bcrypt.CompareHashAndPassword([]byte(tmp.Refresh_token), []byte(tokenReq.Refresh_token)); err != nil {
			user = tmp
			ok = true
			break
		}
	}
	filterCursor.Close(ctx)

	if !ok {
		w.WriteHeader(http.StatusBadRequest) // 500 status
		fmt.Fprintf(w, "Seems like your refresh token doen't exist")
		return
	}

	//////////// removing token pair from db ////////////
	_, err = collection.DeleteOne(ctx, bson.D{{"rT", user.Refresh_token}})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 400 status
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, "Refresh token was deleted")
}

func RemoveAllTokens(w http.ResponseWriter, r *http.Request) {
	guid := mux.Vars(r)["guid"]
	tokenReq, err := parseJson(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 400 status
		fmt.Fprintf(w, err.Error())
		return
	}
	//////////// Check if access token is still valid ////////////
	token, err := tokenParse(tokenReq.Access_token)
	if err != nil || token == nil {
		w.WriteHeader(http.StatusInternalServerError) // 400 status
		return
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized) // 401 status
		fmt.Fprintf(w, "Your token is invalid")
		return
	}
	//////////// retrivieng token pair from db to check guid //////////// !possible vulnerabillity
	var user User
	err = collection.FindOne(ctx, bson.D{{"aT", tokenReq.Access_token}}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, err.Error())
		return
	}

	if user.Guid != guid {
		w.WriteHeader(http.StatusUnauthorized) // 401 status
		fmt.Fprintf(w, "You are not allowed to delete tokens for this user")
		return
	}

	//////////// Deleting all token pairs form db ////////////
	result, err := collection.DeleteMany(ctx, bson.D{{"guid", guid}})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, "%d token pairs were deleted", result.DeletedCount)
}
