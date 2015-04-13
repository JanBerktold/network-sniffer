package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
)

func initConnection() {
	db, err := sql.Open("mysql", dataConnectionString)

	if err != nil {
		log.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("CONNECTION SUCEED")
	}

}
