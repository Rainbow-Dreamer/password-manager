# password-manager

[中文](#密码管理器) English

This is my personal original password manager, using my own original random matrix encryption algorithm to encrypt your password with a very high degree of encryption, the key is a matrix of random numbers, and the dimension of the matrix is related to the total size of your password file.

On the main interface, you can create a password file by clicking the `Create New Password File` button, and then you can click the `Encrypted Output` button to format the generated password text, then perform matrix encryption and output the cipher text and key file.  

You can also write your own password text and then click the `Encrypt File` button to encrypt it, but this password manager has certain requirements for the format of the encrypted password text. First of all, your file should be a text file (.txt file), and then the encoding format must be UTF-8, otherwise it cannot be encrypted. The format of the password file is a python dictionary, which is
```python
{'111': '222', 'aaa': 'bbb', ...}
```
format, with the keys and values being strings for the name of the password and the content of the password, respectively.

Each time the encrypted password file is read and the key file is successfully decrypted, it will display your password in a directory that  

(If the password file is not written in this format before encryption, it will not be displayed properly during decryption and will show decryption failure)  

You can add, delete and check the password, then remember to re-encrypt the saved password by clicking the `encrypt output` button, you will get a brand new cipher text and key file.  

Please keep the key file and the ciphertext file well, and the plaintext file can be deleted.  

The file name of the cipher file generated after each encryption is `password.txt`, and the file name of the key file is `matrix_password.txt`.

# 密码管理器

中文 [English](#password-manager)

这是我个人原创的密码管理器，采用自己原创的随机矩阵加密算法加密你的密码，加密程度非常高，密钥是随机数的矩阵，矩阵的维度和你的密码文件的总大小有关。

在主界面上，大家可以点击`创建全新的密码文件`按钮创建密码文件，然后可以点击`加密输出`按钮进行格式化生成密码文本，然后进行矩阵加密，输出密文和密钥文件。  

大家也可以自己写密码文本然后点击`加密文件`按钮进行加密，不过这个密码管理器对于加密的密码文本的格式有一定的要求。首先你的文件以文本文件为最佳(.txt文件)，然后编码格式一定要是UTF-8，否则无法进行加密。密码文件的格式为python的字典形式，也就是
```python
{'111': '222', 'aaa': 'bbb', ...}
```
的格式，键和值分别为密码的名字和密码的内容的字符串。

每一次读取加密后的密码文件和密钥文件成功解密之后，会在一个目录里显示你的密码，  

(如果密码文件在加密前没有按照这种格式写，在解密的时候无法正常显示，会显示解密失败)  

你可以对密码进行增删改查，然后记得点击`加密输出`按钮对保存后的密码明文进行重新加密，你会得到全新的密文和密钥文件，  

请妥善保管密钥文件，密文的文件也请保管好，明文的文件都可以删了。  

每次加密文件后生成的密文的文件统一的文件名是`password.txt`，密钥文件统一的文件名是  `matrix_password.txt`

