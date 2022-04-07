import { Controller, Post } from "@nestjs/common";
import { AuthService } from "./auth.service";


@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('signup')
    signup() {
        return {
            msg: 'this is signup'
        }
    }


    @Post('signin')
    signin() {
        return {
            msg: 'this is signin'
        }
    }
} 