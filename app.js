let conditional = require('koa-conditional-get');
let etag = require('koa-etag');
let Koa = require('koa');
let req = require('req');
let jwt = require('jsonwebtoken');
let bcrypt = require('bcryptjs');
let router = require('koa-router')();
let path = require("path");
let pug = require("pug");
let fs = require("fs");
let app = new Koa();
let cors = require('kcors');
let uuidv1 = require('uuid/v1');
let nodemailer = require('nodemailer');
app.use(conditional());
app.use(etag());
app.use(cors({
    origin: process.env.OTHER_SUBDOMAIN_URL,
    allowMethods: ['GET', 'POST']
}));

var compiledFunction = pug.compileFile( path.join(__dirname, '//index.pug') );
var htmlpug = compiledFunction({});
var emptyCompiledFunction = pug.compileFile(path.join(__dirname, '//empty.pug'));
var emptypug = emptyCompiledFunction({});

router.get('/sso', sso);
router.get('/ssu', ssu);
router.get('/login', login);
router.get('/signup', signup);
router.get('/pdfreport', pdfreport);
router.get(/^\/local(?:\/|$)/, local);
router.get(/^\/cdn(?:\/|$)/, library);
router.get(/^\/(?:(?!(cdn|sso|local|login|pdfreport|suspend)).)*(?:\/|$)/, main);

app.use(router.routes());

var servio = app.listen(4001);
var io = require('socket.io')(servio);
io.on('connection', function(socket) {
    var client_socket_id;
    socket.on('data1', function(data){
        socket.broadcast.emit('data1', data);
    });
    socket.on('data2', function(data){
        socket.broadcast.emit('data2', data);
    });
    socket.on('data3', function(data){
        socket.broadcast.emit('data3', data);
    });
    socket.on('data4', function(data){
        socket.broadcast.emit('data4', data);
    });
    socket.on('idClient', function( id ){
        if( ! client_socket_id ) client_socket_id = id;
    });
    socket.on('disconnect', function(aa ){
        console.log('disconnect', client_socket_id);
    });
});

var timeexpired = 2 * 60 * 60 * 1000;
var maxWrong = 3;
var rolePlay = {};
var extFile = {
    '.html': "text/html",
    '.jpg': "image/jpeg",
    '.css': "text/css",
    '.js': "text/javascript",
    '.eot': "application/vnd.ms-fontobject",
    '.woff2': "application/font-woff2",
    '.woff': "application/font-woff",
    '.ttf': "application/font-woff",
    '.svg': "image/svg+xml"
};
var urlWindows = path.join(__dirname, '..', '..', '\\html\\www');
var urlHtml = path.join(__dirname, '..', '..', '\\html');

async function library(ctx) {
    var filename = path.join(urlHtml, ctx.url);
    var html2 = await fread(filename, 'binary');
    var html = await stat(filename);
    if (html.isFile() && ['.html', '.css', '.js'].indexOf(path.extname(filename)) == -1) {
        ctx.type = extFile[path.extname(filename)];
        ctx.body = fs.createReadStream(filename);
    } else {
        ctx.type = extFile[path.extname(filename)];
        ctx.body = html2;
    }
}

async function local(ctx) {
    var links = ctx.url.split('/');
    var ref = ctx.request.header.referer.split('/').slice(-1);
    if (ref[0].indexOf('?') > -1)
        ref[0] = ref[0].split('?')[0];
    var filename = path.join(urlWindows, '/' + ref[0] + '/' + links[2]);
    var html = await fread(filename, 'utf8');
    var extentionName = path.extname(filename) in extFile ? extFile[ path.extname(filename) ] : "text/plain";
    ctx.set('Content-Type', extentionName);
    if( extentionName == "text/plain" ) ctx.body = html;
    else ctx.body = html;
}

async function main(ctx) {
    var filename = path.join(urlWindows, ctx.request.path);
    var reqPage = ctx.request.path.substr(1);
    if (fs.statSync(filename).isDirectory()) {
        page = filename.split('\\www\\')[1];
    }
    var html = htmlpug;
    var token = ctx.cookies.get('token');
    console.log(token);
    if (token ) {
        var decoded = jwt.verify(token, 'secret');
        var data = JSON.parse(decoded.data);
        logsystem(data.user, "Opening " + page);
        const n = ~~ctx.cookies.get('view') + 1;
        if (reqPage in rolePlay[data.role]) {
            ctx.cookies.set('view', n);
            ctx.cookies.set('token', token, {
                'maxAge': timeexpired
            });
            ctx.cookies.set('user', data.user, { httpOnly: false });
            ctx.body = html;
        } else {
            ctx.body = '<!DOCTYPE html><html lang="en">You Are Not Allowed</html>';
        }
    } else {

        ctx.redirect('/login');
    }
}

async function login(ctx) {
    ctx.body = emptypug;
}

async function pdfreport(ctx) {
    var filename = path.join(urlWindows, ctx.request.path);
    if (fs.statSync(filename).isDirectory())
        filename += '/index.html';
    var html = await fread(filename, 'utf8');
    ctx.body = html;
}

async function signup(ctx) {
    var filename = path.join(urlWindows, ctx.request.path);
    if (fs.statSync(filename).isDirectory())
        filename += '/index.html';
    var html = await fread(filename, 'utf8');
    ctx.body = html;
}

async function ssu(ctx) {
    var obj = ctx.query;
    var sql = ' SELECT id , CONVERT(COLUMN_JSON(doc) USING utf8) as docs';
    sql += ' FROM docs.roles';
    sql += ' WHERE COLUMN_GET(doc, "username" as char) ="' + ctx.query.username + '" ';
    var res = await req('http://127.0.0.1:8877/test?sql=' + escape(sql));
    var docs = JSON.parse(res);
    if (obj.password && obj.username && obj.role && obj.email && docs.length == 0) {
        var res = await bcrypt.hash(obj.password, 10);
        var id = res.substr(7, 11);
        var sql = ' INSERT INTO docs.roles';
        sql += ' VALUES ("' + id + '", COLUMN_CREATE(';
        sql += ' "username", "' + obj.username + '" ,';
        sql += ' "role", "' + obj.role + '" ,';
        sql += ' "email", "' + obj.email + '",';
        sql += ' "hash", "' + res + '"';
        sql += '))';
        var res = await req('http://127.0.0.1:8877/test?sql=' + escape(sql));
        if (res)
            ctx.body = 'success';
        else
            ctx.body = 'failed';
    } else
        ctx.body = 'failed';
}

async function sso(ctx) {
    var sql = ' SELECT id , CONVERT(COLUMN_JSON(doc) USING utf8) as docs';
    sql += ' FROM docs.roles';
    sql += ' WHERE COLUMN_GET(doc, "username" as char) ="' + ctx.query.username + '" ';
    var res = await req('http://127.0.0.1:8877/test?sql=' + escape(sql));
    var docs = JSON.parse(res);
    console.log(docs);
    var objDoc = JSON.parse(docs[0].docs);
    var nw = ~~ctx.cookies.get('wrong-' + ctx.query.username);
    if ((nw * 1) <= maxWrong && !('suspended' in objDoc) || true) {
        if (docs.length > 0) {
            var obj = JSON.parse(docs[0].docs);
            var res = await bcrypt.compare(ctx.query.password, obj.hash);
            if (res) {
                var token = jwt.sign({
                    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 10),
                    data: JSON.stringify({
                        'user': ctx.query.username,
                        'role': obj.role
                    })
                }, 'secret');
                console.log(ctx.request.header.origin);
                ctx.cookies.set('token', token, {
                    'maxAge': timeexpired,
                    'domain': ctx.request.header.origin
                });
                ctx.cookies.set('wrong-' + ctx.query.username, 0);
                ctx.body = res.toString();
            } else {
                nw = nw + 1;
                ctx.cookies.set('wrong-' + ctx.query.username, nw);
                ctx.body = res.toString();
            }
        } else {
            nw = nw + 1;
            ctx.cookies.set('wrong-' + ctx.query.username, nw);
            ctx.body = 'false';
        }
    } else {
        update(docs[0].id, 'roles', {'suspended':true});
        console.log('Your Account is suspended');
        ctx.cookies.set('wrong-' + ctx.query.username, 0);
        ctx.body = '<!DOCTYPE html><html lang="en">Your Account is suspended</html>';
    }
}

async function logout(ctx) {
    const n = ~~ctx.cookies.get('view');
    ctx.body = n + ' views';
}


let fread = function(filePath, encoding) {
    return new Promise(function(resolve, reject) {
        fs.readFile(filePath, encoding, function(err, data) {
            if (err) {
                console.log('err', filePath);
                return reject(err) // rejects the promise with `err` as the reason   
            }
            resolve(data) // fulfills the promise with `data` as the value
        })
    })
}

let stat = function(file) {
    return new Promise(function(resolve, reject) {
        fs.stat(file, function(err, stat) {
            if (err) {
                console.log('err', file);
                reject(err);
            } else {
                resolve(stat);
            }
        });
    });
}

let logsystem = async function(user, log) {
    var time = new Date(Date.now() + (7 * 3600 * 1000)).toISOString();
    var uid = uuidv1();
    var sql = ' INSERT INTO docs.logsystem';
    sql += ' VALUES ("' + uid + '", COLUMN_CREATE(';
    sql += ' "user", "' + user + '" ,';
    sql += ' "time", "' + time + '" ,';
    sql += ' "log", "' + log + '"';
    sql += '))';
    var res = await req('http://127.0.0.1:8877/test?sql=' + escape(sql));
    console.log(res, sql);
}

let objToArrDB = function (obj) {
    var arr = [];
    Object.keys(obj).forEach(function(e) {
        arr.push(e);
        arr.push(obj[e]);
    });
    return '"' + arr.join('","') + '"';
}

let update = async function(id, table, newObj) {
    var sql = 'SELECT id , CONVERT(COLUMN_JSON(doc) USING utf8) as doc FROM docs.' + table + ' WHERE id="' + id + '"';
    var res = await req('http://127.0.0.1:8877/test?sql=' + escape(sql));
    var obj = JSON.parse(res);
    if (obj.length >= 0) {
        var id = obj[0].id;
        var doc = JSON.parse(obj[0].doc);
        Object.keys(newObj).forEach(function(e) {
            if (newObj[e] == '')
                delete doc[e];
            else
                doc[e] = newObj[e];
        });
        var strData = objToArrDB(doc);
        var del = 'DELETE FROM docs.' + table + ' WHERE id ="' + id + '"';
        var res = await req('http://127.0.0.1:8877/test?sql=' + escape(del));
        var sql = escape('INSERT INTO docs.' + table + ' VALUES ("' + id + '", COLUMN_CREATE(' + strData + '));')
        var res = await req('http://127.0.0.1:8877/test?sql=' + escape(sql));
        return res;
    }
};

let getRoleplay = async function( cb ) {
    var sql = 'SELECT id , CONVERT(COLUMN_JSON(doc) USING utf8) as doc FROM docs.roleplay';
    var res = await req('http://127.0.0.1:8877/test?sql=' + escape(sql));
    var obj = JSON.parse(res);
    var rol = {};
    obj.forEach(function(e) {
        var doc = JSON.parse(e.doc);
        rol[doc.role] = doc;
        delete rol[doc.role]['role'];
    });
    cb(rol);
}


let getConfiguration = async function( cb ) {
    var sql = 'SELECT id , CONVERT(COLUMN_JSON(doc) USING utf8) as doc FROM docs.config';
    var res = await req('http://127.0.0.1:8877/test?sql=' + escape(sql));
    var obj = JSON.parse(res);
    var rol = {};
    cb(obj);
}

setTimeout(function(){
    getRoleplay( function(e){
        rolePlay = e;
        console.log(rolePlay);
    });
    getConfiguration(function(e){
        var doc = JSON.parse(e[0].doc);
        timeexpired = (doc.autologout * 1) * 60 * 1000;
        passexpired = (doc.expiredpassword * 1) * 24 * 60 * 60 * 1000;
        to_emailnotif = doc.to_emailnotif;
        maxWrong =  (doc.wrongpassword * 1) - 1;
        console.log(doc);
    });
}, 1 * 60 * 1000);

/*
setTimeout(function(){
var res = update('Od4AEX3aXH6', 'roles', {'suspended':''});
console.log(res);
}, 1000);
*/
