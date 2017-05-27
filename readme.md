
Goa's googlelogin middlewae


簡単にgoogleloginを行うミドルウェアを作りました。
JWTを発行してsateの検証を行うためDBへの一時保存が不要なほか
login後にもJWTを発行することでセッション管理も不要になっています。




```

End ->  WebApp: start
note right of WebApp: state内にJWT(1)を仕込む

WebApp --> End: redirectURL(stateを含む)
End -> Google : redirectURL(stateを含む)
Google --> End:callback(state含む)
End -> WebApp:callback(state含む)
note right of WebApp: stateの検証(JWT(1)の署名確認):ok
WebApp -> Google:AccessTokenの取得
Google --> WebApp:AccessTokenを渡す
note right of WebApp: AccesTokenからユーザー情報取得しDB保存

note right of WebApp: (公開可能な)ユーザー情報を含むJWT(2)を作成
WebApp -> End: JWT(2)
note right of End: sessonStorageにJWT(2)を保存

End -> WebApp: redirect "/" 
note right of End: 以降のアクセスにJWT(2)を利用

