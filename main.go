package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"

	arg "github.com/alexflint/go-arg"
	"github.com/kataras/go-template/html"
	"github.com/kataras/iris"
)

// TODO: include items from public-dns.info?
// TODO: http://stackoverflow.com/a/31627459/1830159
// TODO: Other thoughts. Type selector,

// Config represents the configuration for the app
type Config struct {
	Debug    bool   `arg:"-d"` // if debugging is enabled or not
	Host     string `arg:"-h"` // hostname/ip to bind to
	Port     int    `arg:"-p"` // port to bind
	Database string // database to utilize
	Resolver string // local resolver
}

// setup some defaults
var conf = Config{
	Debug:    false,
	Host:     "localhost",
	Port:     3000,
	Database: "dns.db",
	Resolver: "127.0.0.1",
}

var logger *log.Logger

func webLogRequest(ctx *iris.Context) {
	logger.Printf("http: request %d from %s for: %s", ctx.ConnRequestNum(), ctx.RemoteIP(), ctx.PathString())

	ctx.Next()
}

func handleError(ctx *iris.Context) {
	ctx.Write("An unknown error occurred")
}

func handleNotFound(ctx *iris.Context) {
	ctx.MustRender("404.html", "")
}

// getWebContext generates the web contexts for use with html templates
func getWebContext(c *iris.Context) map[string]interface{} {
	return iris.Map{
		"Messages": c.GetFlashes(),
	}
}

func saveLookup(results *DNSResults) (string, error) {
	db, err := newDB()
	if err != nil {
		return "", err
	}
	defer db.Clean()

	key := genWord(5, 6)

	return key, db.SetStruct("records", key, results)
}

func getLookup(id string) (*DNSResults, error) {
	db, err := newDB()
	if err != nil {
		return nil, err
	}
	defer db.Clean()

	results := &DNSResults{}

	return results, db.GetStruct("records", id, results)
}

func initWebserver() error {
	logger.Println("initializing webserver")

	iris.Config.Sessions.Cookie = "session"
	iris.Config.LoggerOut = ioutil.Discard
	iris.Config.DisableBanner = true
	iris.Config.Gzip = true
	iris.Config.IsDevelopment = conf.Debug
	iris.StaticWeb("/static", "./static", 1)
	iris.UseTemplate(html.New(html.Config{Layout: "base.html"})).Directory("./static", ".html") //.Binary(Asset, AssetNames)
	iris.UseFunc(webLogRequest)

	// 500
	iris.OnError(iris.StatusInternalServerError, handleError)

	// 404
	iris.OnError(iris.StatusNotFound, handleNotFound)

	iris.Get("/", func(ctx *iris.Context) {
		ctx.MustRender("index.html", getWebContext(ctx))
	})("index")

	iris.Post("/", func(ctx *iris.Context) {
		input := ctx.FormValueString("hosts")
		lookupType := ctx.FormValueString("recordtype")

		hosts, err := parseHosts(input)
		if err != nil {
			ctx.SetFlash("originalHosts", input)
			ctx.SetFlash("error", err.Error())

			ctx.MustRender("index.html", getWebContext(ctx))
			return
		}

		results, err := LookupAll(hosts, "8.8.8.8", lookupType)
		if err != nil {
			ctx.SetFlash("originalHosts", input)
			ctx.SetFlash("error", err.Error())

			ctx.MustRender("index.html", getWebContext(ctx))
			return
		}

		id, err := saveLookup(results)
		if err != nil {
			ctx.SetFlash("originalHosts", input)
			ctx.SetFlash("error", err.Error())

			ctx.MustRender("index.html", getWebContext(ctx))
			return
		}

		ctx.RedirectTo("results", id)
	})

	iris.Get("/r/:key", func(ctx *iris.Context) {
		id := ctx.Param("key")

		result, err := getLookup(id)
		if err != nil {
			fmt.Println(err)

			ctx.MustRender("404.html", "")
			return
		}

		out := getWebContext(ctx)
		out["Results"] = result
		ctx.MustRender("results.html", out)
	})("results")

	listener, err := net.Listen("tcp", conf.Host+":"+strconv.Itoa(conf.Port))
	if err != nil {
		return err
	}

	return iris.Serve(listener)
}

func main() {
	// initialize app flags
	arg.MustParse(&conf)

	// initialize logger
	logger = log.New(os.Stdout, "", log.Lshortfile|log.LstdFlags)
	logger.Println("initializing logger")

	// initialize the database
	initDatabase()

	// initialize webserver
	if err := initWebserver(); err != nil {
		logger.Fatal("error: ", err)
	}
}