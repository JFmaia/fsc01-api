import Router from '@koa/router';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Iniciaaliza o cliente do Prisma
const prisma = new PrismaClient();

// Exportando rotas para outros arquivos
export const router = new Router();

// Carrega varios usuários
router.get('/tweets', async ctx =>{
    // Pegando token do usuário
    const [, token] = ctx.request.header.authorization.split(' ');

    // Se não tem token, retorna erro
    if(!token){
        ctx.status = 401;
        return;
    }
    
    try{
        // decodificando o token
        jwt.verify(token, process.env.JWT_SECRET);

        const tweets = await prisma.tweet.findMany({
            include: {
                user: true,
            }
        });
        ctx.body = tweets;

    }catch(error){

        if(typeof error === 'JsonWebTokenError'){
            ctx.status =401; 
            return
        }
       ctx.status = 500; 
       return
    }
  
})

// Cria um Tweet
router.post('/tweets', async ctx =>{
    // Pegando token do usuário
    const [, token] = ctx.request.header.authorization.split(' ');

    // Se não tem token, retorna erro
    if(!token){
        ctx.status = 401;
        return;
    }

    // Se tem token, verifica se é válido
    try{
        // decodificando o token
        const payload = jwt.verify(token, process.env.JWT_SECRET);

        const tweet = await prisma.tweet.create({
        data: {
            userId: payload.sub,
            text: ctx.request.body.text
        }
    })

    ctx.body = tweet;

    }catch(error){
       ctx.status =401; 
       return
    }
  
})

// Login de usuario
router.get('/login', async ctx =>{
    // Pegando do header o email e senha
    const [, token] = ctx.request.header.authorization.split(' ');
    const [email, plainTextpassword ] = Buffer.from(token, 'base64').toString().split(':');
    
    // Buscando o usuario no banco
    const user = await prisma.user.findUnique({
        where: { email }
    });

    if(!user){
        ctx.body = 404
        return
    }

    // Verificando se a senha está correta
    const passwordMatch = bcrypt.compareSync(plainTextpassword, user.password);

    if(passwordMatch){
        // Gerando o token usando jsonwebtoken
            const accessToken = jwt.sign({
                sub:user.id,
            }, process.env.JWT_SECRET, {expiresIn:'24h'});

        ctx.body = {
            id: user.id,
            name: user.name,
            username: user.username,
            email: user.email,
            accessToken
        };
    
        return
    }

    ctx.body = 404

});

//Cadastra um usuário
router.post('/signup', async ctx =>{
    const saltRounds = 10;
    const password = bcrypt.hashSync(ctx.request.body.password, saltRounds); //criptografa a senha
    
    try {
        const user = await prisma.user.create({
            data:{
                name: ctx.request.body.name,
                username:ctx.request.body.username,
                email: ctx.request.body.email,
                password: password,
            }
        });

        const accessToken = jwt.sign({
            sub:user.id,
        }, process.env.JWT_SECRET, {expiresIn:'24h'});

        ctx.body = {
            id: user.id,
            name: user.name,
            username: user.username,
            email: user.email,
            accessToken,
        };
    
    } catch (error) {
        if(error.meta && !error.meta.target){
            ctx.status = 422
            ctx.body = "Email ou nome de usuario já existe!";
            return 
        }

        ctx.status = 500;
        ctx.body = "Internal server error";
    }
    
})