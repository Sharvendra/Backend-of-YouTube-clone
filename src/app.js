import express from "express";
import cors from "cors"
import cookieparser from "cookie-parser"

const app = express()

app.use(cors({
    origin:process.env.CORS_ORIGIN,
    credentials:true,
}))

//for store data
app.use(express.json({
    limit:"16kb"
}))

app.use(express.urlencoded({extended:true, limit:"16kb"}))

app.use(express.static("public"))
app.use(cookieparser())

//routes import

import userRouter from "./routes/user.routes.js"


//routes declaration
app.use("/api/v1/users", userRouter)

//https://localhost:8000/api/v1/users/...

export {app}