const express = require('express')
const zod=require("zod");
const jwt=require("jsonwebtoken")
const {User}=require("../db");
const {JWT_SECRET} = require("./config");
const { auth } = require('../middleware');

const router=express.Router()

const signupSchema=zod.object({
    username:zod.string().email(),
    password:zod.string().min(6),
    firstName:zod.string(),
    lastName:zod.string()
})

router.post("/signup",async (req,res)=>{
    try{
        const body=req.body;
        const {success}=signupSchema.safeParse(body);
    
        if(!success){
            return res.status(400).json({
                message:"Invalid details"
            })
        }
    
        const exist=await User.findOne({
            username:body.username
        });
    
        if(exist){
            return res.status(409).json({
                message:"Email already exists"
            });
        }
    
        const dbUser=await User.create(body);
    
        const token=jwt.sign({
            userId:dbUser._id
        },JWT_SECRET);
    
        return res.json({
            message: "User created successfully",
            token:token
        });
    }
    catch(err){
        return res.status(500).json({
            message:"Server error"
        });
    }
})

const signinSchema=zod.object({
    username:zod.string().email(),
    password:zod.string()
})

router.post("/signin", async(req,res)=>{
    const {success}=signinSchema.safeParse(req.body);

    if(!success){
        res.status(403).json({
            message:"Incorrect details"
        })
    }

    const user=User.findOne({
        username:req.body.username,
        password:req.body.password
    })

    if(user){
        const token=jwt.sign({
            userId:user._id
        },JWT_SECRET)

        res.json({
            token:token
        })
        return;
    }
    res.status(411).json({
        message: "Error while logging in"
    })
})

const updateSchema=zod.object({
    password:zod.string().optional(),
    firstName:zod.string().optional(),
    lastName:zod.string().optional()
})

router.put("/update",auth,async (req,res)=>{
    const {success}=signinSchema.safeParse(req.body);

    if(!success){
        res.status(403).json({
            message:"Error while updation"
        })
    }

    await User.updateOne(req.body,{
        id:req.userId
    })

    res.json({message:"Update successful"})
})

module.exports=router;