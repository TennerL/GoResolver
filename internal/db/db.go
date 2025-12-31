package db

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func Init() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN environment variable required")
	}

	var err error
	DB, err = sql.Open("mysql", dsn+"?parseTime=true")
	if err != nil {
		log.Fatal("Failed to open DB:", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatal("Failed to ping DB:", err)
	}

	log.Println("Database connected")
}
