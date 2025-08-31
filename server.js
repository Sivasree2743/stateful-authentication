const express=require("express")
const dotenv=require("dotenv")
const mongoose=require("mongoose")
const ejs=require("ejs")
const session=require("express-session")
const MongoDBStore=require("connect-mongodb-session")(session)
const User=require("./models/User")
const bcrypt=require("bcryptjs")
const app=express()
dotenv.config()
app.set("view engine","ejs")
app.use(express.static("public"))
let port=process.env.port || 5555
app.use(express.urlencoded({extended:true}))

// storing session in mongodb

const store=new MongoDBStore({
    uri:process.env.mongo_path,
    collection:"mysession"  
})

// creating session (install express-session)
app.use(session({
    secret:"secret code",
    resave:false,
    saveUninitialized:false,
    store:store
}))

// here the password is not hashed
// app.post("/signup",async(req,res)=>{
//     const {username,email,password}=req.body
//     try{
//         const userDetails=new user({
//         username,
//         email,
//         password
//     })
//     await userDetails.save()
//     res.redirect("/login")
// }catch(err){
//     console.log(err)
//     res.redirect("/register")
// }
// })

// creating middleware

const check_auth=(req,res,next)=>{
    if(req.session.isAuth){
        next()
    }else{
        res.redirect("/register")
    }
}

// hashing password  (reg=>login)

app.post("/signup",async(req,res)=>{
    const {username,email,password}=req.body
    try{
        let existingUser=await User.findOne({email}) // checking the new user 
        if(existingUser){
            return res.send("user already exists")
        }
        const hashesPwd=await bcrypt.hash(password,12)
        const newUser=new User({
        username,
        email,
        password:hashesPwd
    })
    req.session.person=newUser.username
    await newUser.save()
    res.redirect("/login")
}catch(err){
    console.log(err)
    res.status(500).json({message:"server side error"})
}
})

// (login=>dashboard)

app.post("/user-login",async(req,res)=>{
    const {email,password}=req.body
    try{
        const user_details=await User.findOne({email})
        if(!user_details){
            return res.send("user details not found,please register")
        }
        const checkpwd=await bcrypt.compare(password,user_details.password)
        if(!checkpwd){
            return res.send("password in correct")
        }
        req.session.isAuth=true
        res.redirect("/dashboard")
    }catch(err){
        console.log("server side error")
    }
})

// logout

app.post("/logout",(req,res)=>{
    req.session.destroy((err)=>{
        if(err) throw err;
        res.redirect("/register")
    })
})

//-----------------------------------------
app.get("/register",(req,res)=>{
    res.render("register")
})
app.get("/login",(req,res)=>{
    res.render("login")
})
app.get("/dashboard",check_auth,(req,res)=>{
    res.render("dashboard")
})
// connecting database
mongoose.connect(process.env.mongo_path)
.then(()=>{
    console.log("database connected successfully")
}).catch((err)=>{
    console.log("database not connected",err.message)
})

app.listen(port,()=>{
    console.log(`server started at ${port} port`)
})