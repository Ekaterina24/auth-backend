import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.shema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

    constructor(
        @InjectModel(User.name) private UserModel: Model<User>,
        private jwtService: JwtService
    ) {}

    async signup(signupData: SignupDto) {
        const { email, password, name } = signupData

        // check if email is in use
        const emailInUse = await this.UserModel.findOne({
            email
        })
        if (emailInUse) {
            throw new BadRequestException('Email already in use')
        }

        // hash password
        const hashedPassword = await bcrypt.hash(password, 10)
    
        // create user document and save mongodb
        await this.UserModel.create({
            name,
            email,
            password: hashedPassword
        })
    }

    async login(credentials: LoginDto) {
        const { email, password } = credentials

        // find if user exists by email
        const user = await this.UserModel.findOne({ email })
        if (!user) {
            throw new UnauthorizedException('Wrong credentionals')
        }

        // compare entered password with existing password
        const passwordMatch = await bcrypt.compare(password, user.password)
        if (!passwordMatch) {
            throw new UnauthorizedException('Wrong credentials')
        }

        // generate JWT tokens
        return {
            message: 'Success'
        }
    }

    async generateUserTokens(userId) {

        const accessToken = this.jwtService.sign({ userId })
    }
}
