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
	Debug bool   `arg:"-d"` // if debugging is enabled or not
	Host  string `arg:"-h"` // hostname/ip to bind to
	Port  int    `arg:"-p"` // port to bind
}

var logger *log.Logger
var conf = Config{}

func webLogRequest(ctx *iris.Context) {
	logger.Printf("http: request %d from %s for: %s", ctx.ConnRequestNum(), ctx.RemoteIP(), ctx.PathString())

	ctx.Next()
}

func handleError(ctx *iris.Context) {
	ctx.Write("An unknown error occurred")
}

func handleNotFound(ctx *iris.Context) {
	ctx.MustRender("404.html", "", iris.RenderOptions{"layout": iris.NoLayout})
}

func initWebserver() error {
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

	iris.Get("/", func(ctx *iris.Context) { ctx.MustRender("index.html", "") })

	iris.Post("/check", func(ctx *iris.Context) {
		hosts := ctx.FormValueString("hosts")

		fmt.Printf("%#v\n", hosts)

		ctx.MustRender("index.html", "")
	})

	listener, err := net.Listen("tcp", ":"+strconv.Itoa(conf.Port))
	if err != nil {
		return err
	}

	return iris.Serve(listener)
}

func main() {
	conf.Debug = false
	conf.Host = "0.0.0.0"
	conf.Port = 3000
	// initialize app flags
	arg.MustParse(&conf)

	// initialize logger
	logger = log.New(os.Stdout, "", log.Lshortfile|log.LstdFlags)

	// initialize webserver
	if err := initWebserver(); err != nil {
		logger.Fatal("error: ", err)
	}
}
