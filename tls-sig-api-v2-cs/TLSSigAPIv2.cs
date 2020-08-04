﻿using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

using ComponentAce.Compression.Libs.zlib;

namespace tencentyun
{
    public class TLSSigAPIv2
    {
        private readonly int sdkappid;
        private readonly string key;

        public TLSSigAPIv2(int sdkappid, string key)
        {
            this.sdkappid = sdkappid;
            this.key = key;
        }
        /**用于生成实时音视频(TRTC)业务进房权限加密串,具体用途用法参考TRTC文档：https://cloud.tencent.com/document/product/647/32240 
        * TRTC业务进房权限加密串需使用用户定义的userbuf
        * @brief 生成 userbuf
        * @param account 用户名
        * @param dwSdkappid sdkappid
        * @param dwAuthID  数字房间号
        * @param dwExpTime 过期时间：该权限加密串的过期时间，建议300秒.实际过期时间：当前时间 + 过期时间（单位：秒）
        * @param dwPrivilegeMap 用户权限，255表示所有权限
        * @param dwAccountType 用户类型,默认为0
        * @return byte[] userbuf
        */
        public byte[] genUserBuf(string account, uint dwAuthID,int dwExpTime,uint dwPrivilegeMap,uint dwAccountType)
        {
            int length = 1+2+account.Length+20;
            int offset = 0;
            byte[] userBuf = new byte[length];
            
            userBuf[offset++]= 0;

            userBuf[offset++] = (byte)((account.Length & 0xFF00) >> 8);
            userBuf[offset++] = (byte)(account.Length & 0x00FF);
                
            byte[] accountByte = System.Text.Encoding.Default.GetBytes(account);
            accountByte.CopyTo(userBuf, offset);
            offset += account.Length;

            //dwSdkAppid
            userBuf[offset++] = (byte)((sdkappid & 0xFF000000) >> 24);
            userBuf[offset++] = (byte)((sdkappid & 0x00FF0000) >> 16);
            userBuf[offset++] = (byte)((sdkappid & 0x0000FF00) >> 8);
            userBuf[offset++] = (byte)(sdkappid & 0x000000FF);
            
            //dwAuthId
            userBuf[offset++] = (byte)((dwAuthID & 0xFF000000) >> 24);
            userBuf[offset++] = (byte)((dwAuthID & 0x00FF0000) >> 16);
            userBuf[offset++] = (byte)((dwAuthID & 0x0000FF00) >> 8);
            userBuf[offset++] = (byte)(dwAuthID & 0x000000FF);
                
            //time_t now = time(0);
            //uint32_t expire = now + dwExpTime;
            long expire = dwExpTime + (long)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            userBuf[offset++] = (byte)((expire & 0xFF000000) >> 24);
            userBuf[offset++] = (byte)((expire & 0x00FF0000) >> 16);
            userBuf[offset++] = (byte)((expire & 0x0000FF00) >> 8);
            userBuf[offset++] = (byte)(expire & 0x000000FF);

            //dwPrivilegeMap     
            userBuf[offset++] = (byte)((dwPrivilegeMap & 0xFF000000) >> 24);
            userBuf[offset++] = (byte)((dwPrivilegeMap & 0x00FF0000) >> 16);
            userBuf[offset++] = (byte)((dwPrivilegeMap & 0x0000FF00) >> 8);
            userBuf[offset++] = (byte)(dwPrivilegeMap & 0x000000FF);
                
            //dwAccountType
            userBuf[offset++] = (byte)((dwAccountType & 0xFF000000) >> 24);
            userBuf[offset++] = (byte)((dwAccountType & 0x00FF0000) >> 16);
            userBuf[offset++] = (byte)((dwAccountType & 0x0000FF00) >> 8);
            userBuf[offset++] = (byte)(dwAccountType & 0x000000FF);

            return userBuf;
        }
        private static byte[] CompressBytes(byte[] sourceByte)
        {
            MemoryStream inputStream = new MemoryStream(sourceByte);
            Stream outStream = CompressStream(inputStream);
            byte[] outPutByteArray = new byte[outStream.Length];
            outStream.Position = 0;
            outStream.Read(outPutByteArray, 0, outPutByteArray.Length);
            return outPutByteArray;
        }

        private static Stream CompressStream(Stream sourceStream)
        {
            MemoryStream streamOut = new MemoryStream();
            ZOutputStream streamZOut = new ZOutputStream(streamOut, zlibConst.Z_DEFAULT_COMPRESSION);
            CopyStream(sourceStream, streamZOut);
            streamZOut.finish();
            return streamOut;
        }

        public static void CopyStream(System.IO.Stream input, System.IO.Stream output)
        {
            byte[] buffer = new byte[2000];
            int len;
            while ((len = input.Read(buffer, 0, 2000)) > 0)
            {
                output.Write(buffer, 0, len);
            }
            output.Flush();
        }

        private string HMACSHA256(string identifier, long currTime, int expire, string base64UserBuf, bool userBufEnabled)
        {
            string rawContentToBeSigned = "TLS.identifier:" + identifier + "\n"
                 + "TLS.sdkappid:" + sdkappid + "\n"
                 + "TLS.time:" + currTime + "\n"
                 + "TLS.expire:" + expire + "\n";
            if (true == userBufEnabled)
            {
                rawContentToBeSigned += "TLS.userbuf:" + base64UserBuf + "\n";
            }
            using (HMACSHA256 hmac = new HMACSHA256())
            {
                UTF8Encoding encoding = new UTF8Encoding();
                Byte[] textBytes = encoding.GetBytes(rawContentToBeSigned);
                Byte[] keyBytes = encoding.GetBytes(key);
                Byte[] hashBytes;
                using (HMACSHA256 hash = new HMACSHA256(keyBytes))
                    hashBytes = hash.ComputeHash(textBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        private string genUserSig(string userid, int expire, byte[] userbuf, bool userBufEnabled)
        {
            DateTime epoch = new DateTime(1970, 1, 1); // unix 时间戳
            Int64 currTime = (Int64)(DateTime.UtcNow - epoch).TotalMilliseconds / 1000;

            string base64UserBuf;
            string jsonData;
            if (true == userBufEnabled)
            {
                base64UserBuf = Convert.ToBase64String(userbuf);
                string base64sig = HMACSHA256(userid, currTime, expire, base64UserBuf, userBufEnabled);
                // 没有引入 json 库，所以这里手动进行组装
                jsonData = String.Format("{{"
                   + "\"TLS.ver\":" + "\"2.0\","
                   + "\"TLS.identifier\":" + "\"{0}\","
                   + "\"TLS.sdkappid\":" + "{1},"
                   + "\"TLS.expire\":" + "{2},"
                   + "\"TLS.time\":" + "{3},"
                   + "\"TLS.sig\":" + "\"{4}\","
                   + "\"TLS.userbuf\":" + "\"{5}\""
                   + "}}", userid, sdkappid, expire, currTime, base64sig, base64UserBuf);
            }
            else
            {
                // 没有引入 json 库，所以这里手动进行组装
                string base64sig = HMACSHA256(userid, currTime, expire, "", false);
                jsonData = String.Format("{{"
                    + "\"TLS.ver\":" + "\"2.0\","
                    + "\"TLS.identifier\":" + "\"{0}\","
                    + "\"TLS.sdkappid\":" + "{1},"
                    + "\"TLS.expire\":" + "{2},"
                    + "\"TLS.time\":" + "{3},"
                    + "\"TLS.sig\":" + "\"{4}\""
                    + "}}", userid, sdkappid, expire, currTime, base64sig);
            }

            byte[] buffer = Encoding.UTF8.GetBytes(jsonData);
            return Convert.ToBase64String(CompressBytes(buffer))
                .Replace('+', '*').Replace('/', '-').Replace('=', '_');
        }
        /**
        *【功能说明】用于签发 TRTC 和 IM 服务中必须要使用的 UserSig 鉴权票据
        *
        *【参数说明】
        * userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
        * expire - UserSig 票据的过期时间，单位是秒，比如 86400 代表生成的 UserSig 票据在一天后就无法再使用了。
        */
        public string genUserSig(string userid, int expire = 180 * 86400)
        {
            return genUserSig(userid, expire, null, false);
        }

        /**
        *【功能说明】
        * 用于签发 TRTC 进房参数中可选的 PrivateMapKey 权限票据。
        * PrivateMapKey 需要跟 UserSig 一起使用，但 PrivateMapKey 比 UserSig 有更强的权限控制能力：
        *  - UserSig 只能控制某个 UserID 有无使用 TRTC 服务的权限，只要 UserSig 正确，其对应的 UserID 可以进出任意房间。
        *  - PrivateMapKey 则是将 UserID 的权限控制的更加严格，包括能不能进入某个房间，能不能在该房间里上行音视频等等。
        * 如果要开启 PrivateMapKey 严格权限位校验，需要在【实时音视频控制台】=>【应用管理】=>【应用信息】中打开“启动权限密钥”开关。
        *
        *【参数说明】
        * userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
        * roomid - 房间号，用于指定该 userid 可以进入的房间号
        * expire - PrivateMapKey 票据的过期时间，单位是秒，比如 86400 生成的 PrivateMapKey 票据在一天后就无法再使用了。
        * privilegeMap - 权限位，使用了一个字节中的 8 个比特位，分别代表八个具体的功能权限开关：
        *  - 第 1 位：0000 0001 = 1，创建房间的权限
        *  - 第 2 位：0000 0010 = 2，加入房间的权限
        *  - 第 3 位：0000 0100 = 4，发送语音的权限
        *  - 第 4 位：0000 1000 = 8，接收语音的权限
        *  - 第 5 位：0001 0000 = 16，发送视频的权限  
        *  - 第 6 位：0010 0000 = 32，接收视频的权限  
        *  - 第 7 位：0100 0000 = 64，发送辅路（也就是屏幕分享）视频的权限
        *  - 第 8 位：1000 0000 = 200，接收辅路（也就是屏幕分享）视频的权限  
        *  - privilegeMap == 1111 1111 == 255 代表该 userid 在该 roomid 房间内的所有功能权限。
        *  - privilegeMap == 0010 1010 == 42  代表该 userid 拥有加入房间和接收音视频数据的权限，但不具备其他权限。
        */
        public string genPrivateMapKey(string userid, int expire,uint roomid,uint privilegeMap)
        {
            byte[] userbuf = genUserBuf(userid,roomid,expire,privilegeMap,0);
            System.Console.WriteLine(userbuf);
            return genUserSig(userid, expire, userbuf, true);
        }
    }
}
