//Express stuff
const express = require('express');
const session = require('express-session');
//Database and .env stuff
const { MongoStore } = require('connect-mongo');
const dotenv = require('dotenv');
//Encrypting\password hashing stuff/security
const bcrypt = require('bcrypt');
const Joi = require('joi');
const saltRounds = 12;
const mongoSanitize = require('express-mongo-sanitize');

//configures dotenv to use .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;


const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;


app.use(express.urlencoded({extended: true}));  //parse req.body
app.use(express.json());                        //parse json data into req.body
app.use(express.static(__dirname + '/public'));
app.set('view engine', 'ejs');

//for "include to work"
global.include = function(file) 
{
    return require(__dirname + '/' + file);
}

// /**
//  * protect against nosql
//  */
// app.use(mongoSanitize(
//     {replaceWith: '%',
//     allowDots: true
//     }
// ));


//sets up connection to database and makes a collection for users
const {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');
/**
 * Sets up MongoDB session store with encryption.
 */
const mongoStore = MongoStore.create
({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: 
    {
        secret: mongodb_session_secret
    }
}); 

/**
 * Initialize sessions and set up cookie with max age of 1 hour.
 */
app.use(session
({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,               //dont make sesh until something stored in sesh (like req.session.something = "some value")
    resave: true,                           //always save sesh even if nothing changed (save every request)
    cookie: 
    {
        maxAge: 1000 * 60 * 60 * 1          //delets cookie (wristband) after 1 hour  
    }
}));        


/**
 * Some middleware I made for good practice. 
 * I dont really need it since its used once.
 */
function authenticateUser(req, res, next)
{
    if(!req.session.authenticated)
    {
        res.redirect('/login');
        return;
    }
    next();
}

/**
 * Middleware to check if user is admin.
 */
function authenticateAdmin(req, res, next)
{
    if(req.session.user_type !== 'admin')
    {
        res.status(403);

        return res.render('403',
        {
            error: "ADMINS ONLY! you dont have perms here."
        });
    }

    next();
}

/**
 * Main page AKA "Home page".
 * 
 * uses req to send JSON data to client side
 */
app.get('/', (req, res) => 
{
    res.render('index',
        {
            authenticated: req.session.authenticated,
            name: req.session.name
        });
});

/**
 * Signup page.
 */
app.get('/signup', async (req, res) =>
{
    res.render('signup');
});

/**
 * Resoponse for signup submission. 
 * 
 * Uses Joi to validate data and bcrypt 
 * to hash password before storing in database.
 * 
 * I put the async thing cause it uses await.
 */
app.post('/signup', async (req, res) =>
{
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object
    ({
        name : Joi.string().alphanum().min(2).max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().alphanum().min(2).max(20).required()
    });

    const validationResult = schema.validate({name, email, password});

    if(validationResult.error)
    {
        console.log(validationResult.error + " error validating with joi");
        res.redirect('/signup');
        return; 
        //i returned so i dont get error code flow direction split
    }

    //i did it async cause it takes a while with 12 rounds
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne
    ({
        name: name,
        email: email,
        password: hashedPassword,
        user_type: "user"
    });

    //create session and send to members page
    req.session.authenticated = true;

    //storing name in session so i can use it on members page
    req.session.name = name;     
    
    req.session.user_type = "user";
    
    res.redirect('/');
});

/**
 * Login page.
 * 
 * Uses Joi to validate data and bcrypt to compare 
 * password with hashed password in database.
 */
app.get('/login', async (req, res) =>
{
    res.render('login');
});

/**
 * Resonse for login submisssion.
 */
app.post('/login', async(req,res) =>
{
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object
    ({
        email: Joi.string().email().required(),
        password: Joi.string().alphanum().min(2).max(20).required()
    });

    const validationResult = schema.validate({email, password});

    if(validationResult.error)
    {
        console.log(validationResult.error + "error validating with joi");
        res.redirect('/login');
        return;
    }

    //to check if email exists in database
    const user = await userCollection.findOne({email: email});
    if(user && await bcrypt.compare(password, user.password))
    {
        req.session.authenticated = true;
        req.session.name = user.name;       //set session name to name from DB
        req.session.user_type = user.user_type;
        res.redirect('/');
    }
    else
    {
        console.log("wrong password or email");
        res.redirect("/login")
    }
});

app.get('/admin', authenticateUser, authenticateAdmin, async (req, res) => 
{
    //find users.. put them in array.. pass that array in the admin page render
    const usersArray = await userCollection.find().project({name: 1, user_type: 1}).toArray();
    res.render('admin', {users: usersArray});
});

app.post('/promote', authenticateUser, authenticateAdmin, async (req, res) => 
{
    const username = req.body.name;
    await userCollection.updateOne({name: username}, {$set: {user_type: 'admin'}});
    res.redirect('/admin');
});

app.post('/demote', authenticateUser, authenticateAdmin, async (req, res) => 
{
    const username = req.body.name;
    await userCollection.updateOne({name: username}, {$set: {user_type: 'user'}});
    res.redirect('/admin');
});


/**
 * Members only page.
 */
app.get('/members', authenticateUser, (req, res) =>
{
    res.render('members', 
        {
            name: req.session.name
        });
});

/**
 * Will destroy session and redirect back to home.
 */
app.get('/logout', (req, res) =>
{
    req.session.destroy();
    res.redirect('/');
});

app.use((req, res) =>
{
    res.status(404);
    res.render('404');
});

/**
 * Listens on our port.
 */
app.listen(PORT, () =>
{
    console.log(`server run on ${PORT}`);
});