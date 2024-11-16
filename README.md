
# \[OtterCTF 2018] WP



> 题目附件可以在 NSSCTF 上下载，就不贴在这了 \~


# \[OtterCTF 2018] What the password?



> 题目描述：
> 
> 
> you got a sample of rick’s PC's memory. can you get his user password?


先用 vol2 看一下内存镜像信息，版本为Win7SP1x64
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002226133-814957667.png)​
然后用 lsadump 选项导出LSA数据（包含默认密码，如果设置了自动登陆的话），可看到密码
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002226644-702445456.png)​


‍


‍


# \[OtterCTF 2018] General Info



> 题目描述：
> 
> 
> Let's start easy \- whats the PC's name and IP address?


IP查网络连接即可，用 netscan 命令，出现次数最多的 192\.168\.202\.131 就是我们要找的IP
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002227075-692992514.png)​
用 hashdump 命令拿到的用户名提交不对（查了一下主机名和用户名是两个概念），所以我们用hivellist查注册表
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002227488-1841391326.png)​
主机名在 \\REGISTRY\\MACHINE\\SYSTEM 里面，我们用 printkey 命令显示特定位置的信息
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002227883-1776432571.png)​
然后继续跟进ControlSet001
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002228266-855402197.png)​
然后一路跟进，可看到主机名 WIN\-LO6FAF3DTFE
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002228623-1841298047.png)​


‍


‍


# \[OtterCTF 2018] Play Time



> 题目描述：
> 
> 
> Rick just loves to play some good old videogames.
> can you tell which game is he playing?
> whats the IP address of the server?


要找他玩的游戏，用 pslist 查看进程
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002229060-277067948.png)​
然后把进程名复制丢给gpt，问他哪个是游戏，最后知道是 LunarMS 这个游戏
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002229618-187723313.png)​
然后我们用 netscan 命令查看游戏服务器IP，得到 77\.102\.199\.102
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002230055-121362473.png)​


‍


‍


# \[OtterCTF 2018] Name Game



> 题目描述：
> We know that the account was logged in to a channel called Lunar\-3\. what is the account name?


要我们找这个 Lunar\-3 频道的账户名，我们要把 LunarMS.exe 进程的数据拿出来分析
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002230676-342748094.png)​
用 010 打开，搜索字符串 Lunar\-3 ，后面那串就是账户名（没有理由，全是玄学），0tt3r8r33z3
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002231090-302700434.png)​


‍


‍


# \[OtterCTF 2018] Name Game 2



> 题目描述:
> 
> 
> From a little research we found that the username of the logged on character is always after this signature: 0x64 0x??{6\-8} 0x40 0x06 0x??{18} 0x5a 0x0c 0x00{2}
> What's rick's character's name?


他说游戏登录的角色名总是在签名 0x64 0x??{6\-8} 0x40 0x06 0x??{18} 0x5a 0x0c 0x00{2} 后面，这里我们可以在010使用通配符搜索搜索 `4006??????????????????5a0c0000`​，后面的这串字符就是游戏的角色名了，M0rtyL0L
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002231498-108011672.png)​


‍


‍


# \[OtterCTF 2018] Silly Rick



> 题目描述：
> 
> 
> Silly rick always forgets his email's password, so he uses a Stored Password Services online to store his password. He always copy and paste the password so he will not get it wrong. whats rick's email password?


他让找 Rick 的邮箱密码，说他为了不出错总是复制粘贴邮箱密码，我们用 clipboard 命令查看剪切板信息，这个就是密码 M@il\_Pr0vid0rs
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002231888-1530607693.png)​


‍


‍


# \[OtterCTF 2018] Hide And Seek



> 题目描述：
> 
> 
> The reason that we took rick's PC memory dump is because there was a malware infection. Please find the malware process name (including the extension)


让找恶意进程，我们用 pstree 命令查一下进程树
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002232259-1264713501.png)​
发现一个 vmware\-tray.ex ，是 Rick And Morty 的子进程，有点可疑，用 cmdline 看一下这两个进程的命令行
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002232613-2067837579.png)​
这里看到两个 exe 文件，filescan 命令扫描下这两个文件，然后提取出来
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002232969-1880922910.png)​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002233372-717573206.png)​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002233777-2041985434.png)​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002234112-1323959548.png)​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002234524-718178722.png)​
然后我看了下这两个exe，手贱运行了（千万别学，因为谁也想不到赛题里放真马子），然后就知道答案了，vmware\-tray.exe
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002235024-618680643.png)​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002235487-1215182248.png)​


‍


‍


# \[OtterCTF 2018] Path To Glory



> 题目描述：
> 
> 
> How did the malware got to rick's PC? It must be one of rick old illegal habits…


题目问恶意进程怎么进来的，但是我很懵，也不说flag要交啥。。。 我们扫描父进程相关文件
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002235891-766461183.png)​
然后我们主要分析种子文件，将三个种子文件提取出来
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002236282-576807195.png)​
用 strings 看一下可打印字符，发现一个叫website的东西，后面那个就是答案（不理解，应该是题目设置），M3an\_T0rren7\_4\_R!ck
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002236667-895691151.png)​


‍


‍


# \[OtterCTF 2018] Path To Glory 2



> 题目描述：
> 
> 
> Continue the search after the way that malware got in.


这题我更懵，说进一步分析恶意程序怎么进来的。。。去网上搜了下wp，说这个标志说明种子是从网上下载的
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002236988-1038290683.png)​
刚刚 pslist 查进程的时候，Chrome.exe 进程是出现次数最多的，说明是最主要使用的浏览器
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002237393-1505736741.png)​
我们可以使用 filescan 和 dumpfiles 来查找和提取Chrome浏览器历史记录数据库（豆知识：Chrome 将历史数据存储在 SQLite 数据库中）
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002237867-1548762326.png)​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002238258-1531108587.png)​
将后缀名改成 .sqlite，用 sqlite3 执行
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002238649-1764350572.png)​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002239029-1033881435.png)​
执行语句`select current_path, site_url from downloads;`​查询下载路径和url
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002239412-742303695.png)​
可以看到种子文件是从 [https://mail.com](https://github.com) 这个网址下载的，我们将 chrome.exe 进程内存中文件的文件提取出来
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002239806-640149736.png)​
然后我们用 strings 配合 grep 查看这些提取出来的文件，筛选邮箱后缀 `@mail.com`​的前后十行
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002240220-571260253.png)​
这里找到 Rick 的邮箱，有邮箱和密码了，我尝试去登陆邮箱寻找线索，但是显示邮箱/密码错误（毕竟这是个内存取证题，还是老实点吧），然后继续跟进 `rickopicko@mail.com`​的前后二十行，这串很像flag，提交果然是正确的，Hum@n\_I5\_Th3\_Weak3s7\_Link\_In\_Th3\_Ch@in
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002240669-305556400.png)​


‍


‍


# \[OtterCTF 2018] Bit 4 Bit



> 题目描述：
> 
> 
> We've found out that the malware is a ransomware. Find the attacker's bitcoin address.


他说这个恶意软件是勒索软件，让我们找攻击者的比特币地址，把我们刚刚提取出来的 exe 逆向分析，先用 detect 查一下
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002241091-275374603.png)​
是 c\# 写的，用 dnSpy 反编译
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002241593-1575235807.png)​
可以看到有一串的提示信息,然后给出了比特币地址，1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M ，看了网上的WP是这样做的：
一般勒索软件会在桌面上留下勒索信，我们用 filescan查一下桌面的文件
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002242095-1904610964.png)​
可以看到有个 READ\_IT.txt ,还意外发现了 Flag.txt ，一块提取出来，说不定后面有用
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002242481-2127688789.png)​
打开只是个提示文件，还是要分析恶意进程内存里的信息，继续提取
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002242834-2033637757.png)​
然后用 strings \-el （这个参数是显示unicode编码的字符串）配合 grep 查看进程内存里面信息，可以看到对话信息，后面给出了比特币提交地址，1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002243181-1783911127.png)​


‍


‍


# \[OtterCTF 2018] Graphic's For The Weak



> 题目描述：
> 
> 
> There's something fishy in the malware's graphics.


他说恶意软件的图标有些可疑，那我们继续分析，在资源里可以看到软件图标，上面就有flag， S0\_Just\_M0v3\_Socy
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002243695-828212787.png)​


‍


‍


# \[OtterCTF 2018] Recovery



> 题目描述：
> 
> 
> Rick got to have his files recovered! What is the random password used to encrypt the files?


这题让找加密文件的随机密码，继续分析找到两个函数 `CreatePassword`​ `SendPassword`​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002244272-93174103.png)​
可以知道随机密码是`CreatePassword`​函数生成的，然后由`SendPassword`​函数与计算机名、用户名拼接发送，这样我们用strings 配合 grep 在恶意进程进程内存中搜索，得到 加密文件的随机密码，aDOBofVYUNVnmp7
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002244694-1925443055.png)​


‍


‍


# \[OtterCTF 2018] Closure



> 题目描述：
> 
> 
> Now that you extracted the password from the memory, could you decrypt rick's files?


题目让解密 Rick 的文件，之前在桌面提取一个 Flag.txt 出来了，也许就是解密这个文件，我们先看这个加密文件的函数 `EncryptFile`​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002245112-268742042.png)​
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002245588-174220892.png)​
可以知道，先把 password 转成字节，然后用 sha256 计算 password 的哈希作为 AES（魔改） 的密钥对文件进行加密，然后在文件名后面加上 .WINDOWS ，那么我们写脚本解密就好了，注意把 Flag.txt 后面的空字节删了
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002246016-1859403232.png)​
解密脚本如下，丢给GPT写的，想改成python的代码，但是解密的文本总是乱码，就放弃了



```
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp5
{
    internal class Program
    {
        static void Main(string[] args)
        {

            string filePath = @"Flag.txt";
            string password = "aDOBofVYUNVnmp7";

            Program program = new Program();
            //加密段落
            //program.EncryptFile(filePath, password);

            //Console.WriteLine("文件已加密，请勿泄露！");

            //Console.ReadLine();

            //解密段落
            program.DecryptFile(filePath, password);

            Console.WriteLine("文件已解密！");

            Console.ReadLine();

        }
        public void EncryptFile(string file, string password)
        {
            byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
            byte[] array = Encoding.UTF8.GetBytes(password);
            array = SHA256.Create().ComputeHash(array);
            byte[] bytes=this.AES_Encrypt(bytesToBeEncrypted, array);
            File.WriteAllBytes(file, bytes);
            File.Move(file, file + ".WINDOWS");
        }


        public void DecryptFile(string file, string password)
        {
            string encryptedFilePath = file + ".WINDOWS";

            byte[] bytesToBeDecrypted = File.ReadAllBytes(encryptedFilePath);

            byte[] array = Encoding.UTF8.GetBytes(password);
            array = SHA256.Create().ComputeHash(array);

            byte[] decryptedBytes = this.AES_Decrypt(bytesToBeDecrypted, array);

            File.WriteAllBytes(file, decryptedBytes);

            File.Delete(encryptedFilePath);
        }

      

        public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] result = null;
            byte[] salt = new byte[]
            {
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8
            };
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                {
                    rijndaelManaged.KeySize = 256;
                    rijndaelManaged.BlockSize = 128;
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
                    rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
                    rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
                    rijndaelManaged.Mode = CipherMode.CBC;
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cryptoStream.Close();
                    }
                    result = memoryStream.ToArray();
                }
            }
            return result;
        }
        private byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            byte[] salt = new byte[]
{
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8
};
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }
    }
}

```

不出所料，解密的文件里有flag，CTF{Im\_Th@\_B3S7\_RicK\_0f\_Th3m\_4ll}
​![image](https://img2023.cnblogs.com/blog/3400631/202411/3400631-20241116002246403-1856461826.png)​


  * [\[OtterCTF 2018] WP](#otterctf-2018-wp)
* [\[OtterCTF 2018] What the password?](#otterctf-2018-what-the-password)
* [\[OtterCTF 2018] General Info](#otterctf-2018-general-info)
* [\[OtterCTF 2018] Play Time](#otterctf-2018-play-time)
* [\[OtterCTF 2018] Name Game](#otterctf-2018-name-game)
* [\[OtterCTF 2018] Name Game 2](#otterctf-2018-name-game-2)
* [\[OtterCTF 2018] Silly Rick](#otterctf-2018-silly-rick)
* [\[OtterCTF 2018] Hide And Seek](#otterctf-2018-hide-and-seek)
* [\[OtterCTF 2018] Path To Glory](#otterctf-2018-path-to-glory)
* [\[OtterCTF 2018] Path To Glory 2](#otterctf-2018-path-to-glory-2):[FlowerCloud机场](https://yunbeijia.com)
* [\[OtterCTF 2018] Bit 4 Bit](#otterctf-2018-bit-4-bit)
* [\[OtterCTF 2018] Graphic's For The Weak](#otterctf-2018-graphics-for-the-weak)
* [\[OtterCTF 2018] Recovery](#otterctf-2018-recovery)
* [\[OtterCTF 2018] Closure](#otterctf-2018-closure)

   ![](https://github.com/avatar/3400631/20240622171012.png)    - **本文作者：** [MiaCTFer](https://github.com)
 - **本文链接：** [https://github.com/MiaCTFer/p/18548926/otterctf\-2018\-wp\-zbokhg](https://github.com)
 - **关于博主：** 评论和私信会在第一时间回复。或者[直接私信](https://github.com)我。
 - **版权声明：** 本博客所有文章除特别声明外，均采用 [BY\-NC\-SA](https://github.com "BY-NC-SA") 许可协议。转载请注明出处！
 - **声援博主：** 如果您觉得文章对您有帮助，可以点击文章右下角**【[推荐](javascript:void(0);)】**一下。
     
