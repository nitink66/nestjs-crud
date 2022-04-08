import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prismaModule/prisma.service";
import { AuthDTO } from "./dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) { }

    async signup(dto: AuthDTO) {
        try {
            //generate the password hash 
            const hash = await argon.hash(dto.password);

            // save the new user in db
            const user = await this.prisma.user.create({
                data: {
                    firstName: 'test',
                    email: dto.email,
                    hash,
                },
                //select only required fields from db and return
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    createdAt: true
                }
            })

            // return the saved user
            // return user;
            return this.signToken(user.id, user.email)

        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                // P2002  code used to throw duplicate value in db from prisma    
                if (error.code === 'P2002') {
                    throw new ForbiddenException(`User with ${dto.email} already exist`)
                }
            }
            throw error;
        }
    }

    async login(dto: AuthDTO) {
        //find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            }
        });

        // if user not found throw exception
        if (!user) throw new ForbiddenException("Email Does not exist")

        // compare password with argon
        const pwdMatches = await argon.verify(user.hash, dto.password)

        // send error if password doesn't match
        if (!pwdMatches) throw new ForbiddenException("Password does not match ")

        //delete user hash from db
        // delete user.hash
        //return user
        return this.signToken(user.id, user.email)
    }


    async signToken(userId: number, email: string): Promise<{ access_token: string }> {
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get('DATABASE_URL')

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret
        })

        return {
            access_token: token
        }


    }
}