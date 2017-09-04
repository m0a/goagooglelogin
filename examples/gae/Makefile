#! /usr/bin/make
#
# Makefile for goa examples in appengine
#
# Targets:
# - appengine
# This command makes necessary changes to use with GAE / Go.
# Also, please be sure to vendoring If you use this command.
#

##### Example ######

example: depend bootstrap delete 

delete:
	rm -f ./hello.go
	rm -f ./main.go

##### Convenience targets ######

REPO:=github.com/m0a/goagooglelogin/examples/gae
GAE_PROJECT:=gae-sandboxz
PORT:=8080


init:  bootstrap controllers
gen: clean generate 

# depend:
# 	@which glide || go get -v github.com/Masterminds/glide
# 	@glide install

controllers:
	@goagen main -d $(REPO)/design -o controllers

bootstrap:
	@goagen bootstrap -d $(REPO)/design

main:
	@goagen main -d $(REPO)/design

clean:
	@rm -rf app
	@rm -rf client
	@rm -rf tool
	@rm -rf swagger

generate:
	@go generate

deploy:
	goapp deploy -application $(GAE_PROJECT) ./server

rollback:
	appcfg.py rollback ./server -A $(GAE_PROJECT)

local:
	goapp serve -port $(PORT) ./server
