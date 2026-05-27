import jwt from "jsonwebtoken";
import { config } from "./config.js";
import { supabase } from "./supabase.js";
export const signAuthToken = (user) => jwt.sign({
    sub: user.id,
    email: user.email,
    name: user.name
}, config.jwtSecret, { expiresIn: "7d" });
export const clearAuthCookie = (res) => {
    res.clearCookie(config.cookieName);
};
export const verifyToken = (token) => jwt.verify(token, config.jwtSecret);
export const getUserFromToken = async (token) => {
    if (!token)
        return null;
    const payload = verifyToken(token);
    const { data, error } = await supabase
        .from("users")
        .select("*")
        .eq("id", payload.sub)
        .single();
    if (error || !data)
        return null;
    return data;
};
const extractToken = (req) => {
    const auth = req.headers.authorization;
    if (auth?.startsWith("Bearer "))
        return auth.slice(7);
    return req.cookies?.[config.cookieName];
};
export const requireAuth = async (req, res, next) => {
    try {
        const user = await getUserFromToken(extractToken(req));
        if (!user) {
            res.status(401).json({ error: "Not authenticated" });
            return;
        }
        req.currentUser = user;
        next();
    }
    catch {
        res.status(401).json({ error: "Invalid session" });
    }
};
