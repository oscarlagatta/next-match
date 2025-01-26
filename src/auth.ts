import NextAuth from "next-auth"
import { PrismaAdapter } from "@auth/prisma-adapter"
import { prisma } from "@/lib/prisma"
import CredentialsProvider from "next-auth/providers/credentials";
import {getUserByEmail} from "@/app/actions/authActions";
import bcrypt from "bcryptjs";

export const { handlers, auth, signIn, signOut } = NextAuth({
    callbacks: {
        async session({token, session}) {

            if(token.sub && session.user) {
                session.user.id = token.sub;
            }

            console.log(
                "Session callback called with token:",
                token,
                "session:",
                session
            )

            return session;
        }
    },
    adapter: PrismaAdapter(prisma),
    providers: [CredentialsProvider({
        name: "Credentials", // Ensure this matches the provider name used in `signIn`
        credentials: {
            email: { label: "Email", type: "text" },
            password: { label: "Password", type: "password" },
        },
        async authorize(credentials) {
            console.log("Authorize function called with:", credentials);

            // Validate the credentials object
            if (!credentials?.email || !credentials?.password) {
                console.error("Missing email or password");
                return null;
            }

            // Fetch the user by email
            const user = await getUserByEmail(credentials.email as string);
            if (!user) {
                console.error("No user found with the provided email");
                return null;
            }

            // Validate the password
            const isPasswordValid = await bcrypt.compare(
                credentials.password as string,
                user.passwordHash
            );
            if (!isPasswordValid) {
                console.error("Invalid password");
                return null;
            }

            // If authentication is successful, return the user object
            console.log("User authenticated successfully:", user);
            return {
                id: user.id,
                email: user.email,
                name: user.name,
            };
        },
    })],
    session: {
        strategy: 'jwt'
    },
});