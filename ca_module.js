//express 불러오기
const { response } = require("express");
const express = require("express");
const { request } = require("http");
const bodyParser = require('body-parser');
const { generateKeyPairSync, publicDecrypt } = require("crypto");
const mysql = require("mysql");

//jwt
const jwt = require('jsonwebtoken');
const expressJWT = require('express-jwt');
const bearerToken = require('express-bearer-token');

//express 사용
const app = express();

//포트 번호 설정
const port = 4000;

//http 서버 실행
app.listen(port,() => {
    console.log("server start on 4000");
})

//파일
var fs = require('fs'); 

// node.js 모듈(body-parser)
// 클라이언트 POST request data의 body로부터 파라미터를 편리하게 추출
app.use(bodyParser.json());

/*
	false면 기본으로 내장된 querystring 모듈을 사용하고
	true면 따로 설치가 필요한 qs 모듈을 사용하여 쿼리 스트링을 해석
	기존 querystring 모듈과 qs 모듈의 차이는 중첩 객체 처리라고 보면 됨
*/
app.use(express.urlencoded({extended: false}));



app.set('secret', 'thisismysecret');
app.use(bearerToken());


app.use(expressJWT({
    secret: 'thisismysecret',
    algorithms: ['HS256']
}).unless({
  path: ['/users', '/test']
}));

app.use((req, res, next) => {
//   console.log('New req for %s', req.originalUrl);
    if (req.originalUrl.indexOf('/users') >= 0 || req.originalUrl.indexOf('/test') >= 0) {
        return next();
    }
    var token = req.token;
    jwt.verify(token, app.get('secret'), (err, decoded) => {
        if (err) {
            console.log(`Error ================:${err}`)
            res.send({
                success: false,
                message: 'Failed to authenticate token. Make sure to include the ' +
                    'token returned from /users call in the authorization header ' +
                    ' as a Bearer token'
            });
            return;
        } else {
            req.username = decoded.username;
	    console.log( decoded.username);
            return next();
        }
    });
});

/*
const client = mysql.createConnection({
           user:'root',
           host:'127.0.0.1',
	   port:3306,
           database:'ca_db',
           password:'elwlxjfwhs1!', 
});

client.connect();
*/

app.post('/users', async function (request,response) {

	var username = request.body.username;
	
	if (!username || !(username==='certificate_authority')) {
		res.json(getErrorMessage('\'username\''));
		return;
	}

	var token = jwt.sign({
        	username: username,
    	}, app.get('secret') ,{ expiresIn: "5m" });


        const response1  = {
		success: "true",
		token: token,
		error: null
        }

        response.status(200).send(response1)

});


// http:/localhost:4000/ 경로로 접근시
app.post("/ca", async (request,response) => {

	var did = request.body.did;
	
	var status = "good";

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

	// 값이 없으면 insert, 값이 있으면 update
	var sql = 'INSERT INTO ca (did,pubkey,status) VALUES(?,?,?) ON DUPLICATE KEY UPDATE pubkey=?, status=?';

	var param = [ did , publicKey, status, publicKey, status]

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
		status : status,
		error: null
        };

	var enc_response = Buffer.from(JSON.stringify(response1), "utf8").toString('base64');
	console.log("enc_response : " + enc_response);

	//var dec_response = Buffer.from(enc_response, "base64").toString('utf8');
	//console.log("dec_response: " + dec_response);
	//console.log("response : " + JSON.parse(dec_response));

        response.status(200).send(enc_response);
    
});


// http:/localhost:4000/ 경로로 접근시
app.post("/auth", async (request,response) => {

	var did = request.body.did;
	var enc_mes = request.body.enc_mes;
	var check = "false";

	enc_mes = Buffer.from(enc_mes, "base64").toString('utf8');

        var sql = 'SELECT pubkey FROM ca WHERE did=?';

        var param = [ did ]

	var pubkey;

        client.query(sql, param, function(err, res, fields){
                
		if(err){
                        console.log(err);
                }

                var response1;
                if(res[0] == null){
                        response1  = {
                                success: "false",
                                error: "not exist did"
                        }
                }else{

			pubkey = res[0].pubkey;
			try{
				var plaintext = publicDecrypt(pubkey, Buffer.from(enc_mes, 'base64'));
			        console.log(plaintext.toString());
		
                	        if(plaintext.toString() == "check"){
                        	        check = "true"
                       		}
                       		response1  = {
                               		success: check,
                                	error: null
                        	}

			}catch(err){
                                response1  = {
                                        success: "false",
                                        error: "Invalid Did"
                                }
			}
		}

	        response.status(200).send(response1)
        });
});


// http:/localhost:4000/ 경로로 접근시
app.post("/check", async (request,response) => {

	var did = request.body.did;

	var sql = 'SELECT status FROM ca WHERE did=?';
	
	var param = [ did ];
	var response1;
	client.query(sql, param, function(err, res, fields){
                
		if(err){
                        console.log(err);
                }
		var response1;
                if(res[0] == null){
                        response1  = {
                                success: "false",
                                error: "not exist did"
                        }
                }else{
	                response1  = {
       	 	                success: "true",
				status : res[0].status,
                       		error: null
                	}
		}

                response.status(200).send(response1);
        });

});

// http:/localhost:4000/ 경로로 접근시
app.post("/expire", async (request,response) => {

        var did = request.body.did;
	var status = "revoked";

	var sql = 'SELECT status FROM ca WHERE did=?';
        var param = [ did ];
        client.query(sql, param, function(err, res, fields){
                if(err){
			console.log(err);
                }
		var response1;
		if(res[0] == null){
        		response1  = {
             			success: "false",
             			error: "not exist did"
        		}
		}else{
        		var sql = 'UPDATE ca SET status = ? WHERE did = ?';

        		var param = [ status , did ]

        		client.query(sql,param, function(err, res, fields){
                	if(err){
                        	console.log(err);
                	}
                	console.log("Insert Clear");
        		});

        		response1  = {
             		success: "true",
             		did : did,
             		status : status,
             		error: null
			}
        	}

		response.status(200).send(response1)

        });
});

// http:/localhost:4000/ 경로로 접근시
app.post("/test", async (request,response) => {
		
		var qq;

		qq = fs.readFileSync('./testtest.txt','utf-8');
	
		const response1 = {
                        test : qq,
                        error: null
                }

                response.status(200).send(response1);
});


