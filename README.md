voce tem que mudar os valores de inicio e de busca dentro do codigo para procurar outros valores, esse programa busca pelo rpm160 da chave publica.
isso é algo facilmente achavel.
o valor padrao leva uns 40 segundos para ser encontrado.

`Download:`
```bash
git clone https://github.com/juliano-xd/Finder.git && cd Finder
```
Voce vai precisar ter a biblioteca ```secp256k1-dev``` em seu computador.

`Para rodar o programa:`
```bash
gcc -o finder finder.c -lsecp256k1 -lsodium -lcrypto
```
`e depois:`
```
./finder
```
