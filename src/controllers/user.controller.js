import { asynchandler } from "../utils/asynchandler.js";
import { ApiError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    // console.log(user)
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    console.log(user.generateAccessToken());
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const registerUser = asynchandler(async (req, res) => {
  // res.status(200).json({
  //     message:"ok done"
  // })
  //for check server is running or  not
  //get user details from frontend
  //validation - not empty
  //check if user already exists : username, email
  //check for images , check for avatar
  //upload them to cloudinary, avatar
  //create user object - create entry in db
  //remove and refresh token field from response
  // check for user creation
  //return res

  const { fullname, email, username, password } = req.body;
  console.log("email : ", email);

  //   if(fullname === ""){
  //     throw new ApiError(400, "fullname is required")
  //   }
  if (
    [fullname, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required ");
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }
  // console.log(req.files);

  const avatarLocalPath = req.files?.avatar[0]?.path;
  //   const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  )
    if (!avatarLocalPath) {
      throw new ApiError(400, "Avatar file is required");
    }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  if (!createdUser) {
    throw new ApiError(500, "Somthing wnet while registering the user");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
  //  .end()
});

const loginUser = asynchandler(async (req, res) => {
  //req body -> data
  // username or email
  // find the user
  // password check
  // access and refresh token
  //send cookie

  const { email, username, password } = req.body;

  // console.log(username, password);

  if (!username && !email) {
    throw new ApiError(400, "username or email is required");
  }

  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(400, "User does not exist");
  }
  // console.log(user.password)
  const isPasswordValid = await user.isPasswordCorrect(password);

  console.log(isPasswordValid);
  //isPasswordCorrect(password)
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid used credentials");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );
  // console.log(user._id)
  // console.log(accessToken, refreshToken)
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  // console.log(loggedInUser)
  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in Successfully"
      )
    );
});

const logoutUser = asynchandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"));
});

const refreshAccessToken = asynchandler(async(req, res)=>{
 const incommingRefreshToken= req.cookies.refreshToken || req.body.refreshToken
 if(!incommingRefreshToken){
  throw new ApiError(401, "unatuthorized request")
 }

 try {
  const decodedToken = jwt.verify(
   incommingRefreshToken, 
   process.env.REFRESH_TOKEN_SECRET)
 
 const user = await  User.findById(decodedToken?._id)
 
 if(!user){
   throw new ApiError(401, "Invalid refresh token")
  }
 
  if(incommingRefreshToken !== user?.refreshToken){
     throw new ApiError(401, "Refresh token is expired or used")
  }
 
  const options = {
   httpOnly: true,
   secure: true
  }
 
  const {accessToken, newrefreshToken} =await generateAccessAndRefreshTokens(user._id)
 
  return res
  .status(200)
  .cookie("accessToken",accessToken, options)
  .cookie("refreshToken", newrefreshToken, options)
  .json(
   new ApiResponse(
     200,
     {accessToken, refreshToken: newrefreshToken},
     "Access token refreshed"
   )
  )
 
 } catch (error) {
  throw new ApiError(401, error?.message || "Invalid deocedToken")
 }
})

export { registerUser,
   loginUser,
    logoutUser,
    refreshAccessToken
   };
