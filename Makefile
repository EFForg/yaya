


build:
	go get github.com/EFForg/yaya
	cd $GOPATH/src/github.com/EFForg/yaya
	go build 
	go install 

dockerrun:
	docker build -t yaya .	
	docker run -it yaya

clean:
	rm yaya
