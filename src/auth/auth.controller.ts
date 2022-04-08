import { Body, Controller, ParseIntPipe, Post } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDTO } from "./dto";


@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('signup')
    signup(
        @Body() dto: AuthDTO
        // @Body('email') email: string,
        // @Body('password', ParseIntPipe) password: string
    ) {
        console.log({
            email: dto.email,
            password: dto.password
        })
        return this.authService.signup(dto)
    }


    @Post('login')
    login(@Body() dto: AuthDTO) {
        return this.authService.login(dto)
    }
} 