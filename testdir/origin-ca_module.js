//express 불러오기
const { response } = require("express");
const express = require("express");
const { request } = require("http");
const bodyParser = require('body-parser');
const { generateKeyPairSync, publicDecrypt } = require("crypto");
const mysql = require("mysql");

//express 사용
const app = express();

//포트 번호 설정
const port = 4000;

//http 서버 실행
app.listen(port,() => {
    console.log("server start on 4000");
})

// node.js 모듈(body-parser)
// 클라이언트 POST request data의 body로부터 파라미터를 편리하게 추출
app.use(bodyParser.json());

/*
	false면 기본으로 내장된 querystring 모듈을 사용하고
	true면 따로 설치가 필요한 qs 모듈을 사용하여 쿼리 스트링을 해석
	기존 querystring 모듈과 qs 모듈의 차이는 중첩 객체 처리라고 보면 됨
*/
app.use(express.urlencoded({extended: false}));


const client = mysql.createConnection({
           user:'root',
           host:'127.0.0.1',
	   port:3306,
           database:'ca_db',
           password:'elwlxjfwhs1!', 
});

client.connect();


// http:/localhost:4000/ 경로로 접근시
app.post("/ca", async (request,response) => {

	var did = request.body.did;

	const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  						modulusLength: 1024,
  						publicKeyEncoding: {
    							type: 'spki',
    							format: 'pem'
  						},
  						privateKeyEncoding: {
    							type: 'pkcs8',
    							format: 'pem',
  						}
					});
	console.log("Public Key is: ", publicKey);
        console.log();
        console.log("Private Key is: ", privateKey);


	var sql = 'INSERT INTO ca (did,pubkey) VALUES(?,?) ON DUPLICATE KEY UPDATE pubkey=?';

	var param = [ did , publicKey, publicKey]

	client.query(sql,param, function(err, res, fields){
		if(err){
			console.log(err);
		}
		console.log("Insert Clear");
	});
	

        const response1  = {
             success: "true",
	     did : did,
	     privkey : privateKey,
             error: null
        }

        response.status(200).send(response1)
    
});


// http:/localhost:4000/ 경로로 접근시
app.post("/verify", async (request,response) => {

	var did = request.body.did;
	var enc_mes = request.body.enc_mes;
	var check = "false";


        var sql = 'SELECT pubkey FROM ca WHERE did=?';

        var param = [ did ]

	var pubkey;

        await client.query(sql,param, function(err, res, fields){
                if(err){
                        console.log(err);
                }
		pubkey = res[0].pubkey;
		console.log(pubkey);
		var plaintext = publicDecrypt(pubkey, Buffer.from(enc_mes, 'base64'));

        	console.log(plaintext.toString());


		if(plaintext.toString() == "check"){
			check = "true"
		}
        	const response1  = {
             		success: check,
             		error: null
        	}

	        response.status(200).send(response1)
        });
});


app.get("/set",  async (request,response) => {


});
