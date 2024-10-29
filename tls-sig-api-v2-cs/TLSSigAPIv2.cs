using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

using ComponentAce.Compression.Libs.zlib;

namespace tencentcloud
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

        /**
        * Function: Used to issue UserSig that is required by the TRTC and IM services.
        *
        * Parameter description:
        * userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
        * expire - UserSig expiration time, in seconds. For example, 86400 indicates that the generated UserSig will expire one day after being generated.
        */
        public string genUserSig(string userid, int expire = 180 * 86400)
        {
            return genUserSig(userid, expire, null, false);
        }

        /**
        * Function:
        * Used to issue PrivateMapKey that is optional for room entry.
        * PrivateMapKey must be used together with UserSig but with more powerful permission control capabilities.
        *  - UserSig can only control whether a UserID has permission to use the TRTC service. As long as the UserSig is correct, the user with the corresponding UserID can enter or leave any room.
        *  - PrivateMapKey specifies more stringent permissions for a UserID, including whether the UserID can be used to enter a specific room and perform audio/video upstreaming in the room.
        * To enable stringent PrivateMapKey permission bit verification, you need to enable permission key in TRTC console > Application Management > Application Info.
        *
        * Parameter description:
        * userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
        * roomid - ID of the room to which the specified UserID can enter.
        * expire - PrivateMapKey expiration time, in seconds. For example, 86400 indicates that the generated PrivateMapKey will expire one day after being generated.
        * privilegeMap - Permission bits. Eight bits in the same byte are used as the permission switches of eight specific features:
        *  - Bit 1: 0000 0001 = 1, permission for room creation
        *  - Bit 2: 0000 0010 = 2, permission for room entry
        *  - Bit 3: 0000 0100 = 4, permission for audio sending
        *  - Bit 4: 0000 1000 = 8, permission for audio receiving
        *  - Bit 5: 0001 0000 = 16, permission for video sending
        *  - Bit 6: 0010 0000 = 32, permission for video receiving
        *  - Bit 7: 0100 0000 = 64, permission for substream video sending (screen sharing)
        *  - Bit 8: 1000 0000 = 200, permission for substream video receiving (screen sharing)
        *  - privilegeMap == 1111 1111 == 255: Indicates that the UserID has all feature permissions of the room specified by roomid.
        *  - privilegeMap == 0010 1010 == 42: Indicates that the UserID has only the permissions to enter the room and receive audio/video data.
        */
        public string genPrivateMapKey(string userid, int expire, uint roomid, uint privilegeMap)
        {
            byte[] userbuf = genUserBuf(userid, roomid, expire, privilegeMap, 0,"");
            System.Console.WriteLine(userbuf);
            return genUserSig(userid, expire, userbuf, true);
        }
        
        /**
        * Function:
        * Used to issue PrivateMapKey that is optional for room entry.
        * PrivateMapKey must be used together with UserSig but with more powerful permission control capabilities.
        *  - UserSig can only control whether a UserID has permission to use the TRTC service. As long as the UserSig is correct, the user with the corresponding UserID can enter or leave any room.
        *  - PrivateMapKey specifies more stringent permissions for a UserID, including whether the UserID can be used to enter a specific room and perform audio/video upstreaming in the room.
        * To enable stringent PrivateMapKey permission bit verification, you need to enable permission key in TRTC console > Application Management > Application Info.
        *
        * Parameter description:
        * userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
        * roomstr - ID of the room to which the specified UserID can enter.
        * expire - PrivateMapKey expiration time, in seconds. For example, 86400 indicates that the generated PrivateMapKey will expire one day after being generated.
        * privilegeMap - Permission bits. Eight bits in the same byte are used as the permission switches of eight specific features:
        *  - Bit 1: 0000 0001 = 1, permission for room creation
        *  - Bit 2: 0000 0010 = 2, permission for room entry
        *  - Bit 3: 0000 0100 = 4, permission for audio sending
        *  - Bit 4: 0000 1000 = 8, permission for audio receiving
        *  - Bit 5: 0001 0000 = 16, permission for video sending
        *  - Bit 6: 0010 0000 = 32, permission for video receiving
        *  - Bit 7: 0100 0000 = 64, permission for substream video sending (screen sharing)
        *  - Bit 8: 1000 0000 = 200, permission for substream video receiving (screen sharing)
        *  - privilegeMap == 1111 1111 == 255: Indicates that the UserID has all feature permissions of the room specified by roomid.
        *  - privilegeMap == 0010 1010 == 42: Indicates that the UserID has only the permissions to enter the room and receive audio/video data.
        */
        public string genPrivateMapKeyWithStringRoomID(string userid, int expire, string roomstr, uint privilegeMap)
        {
            byte[] userbuf = genUserBuf(userid, 0, expire, privilegeMap, 0,roomstr);
            System.Console.WriteLine(userbuf);
            return genUserSig(userid, expire, userbuf, true);
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
                // The json library is not imported, so it is assembled manually here
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
                // The json library is not imported, so it is assembled manually here
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
        public byte[] genUserBuf(string account, uint dwAuthID, int dwExpTime, uint dwPrivilegeMap, uint dwAccountType,string roomStr)
        {
            int length = 1 + 2 + account.Length + 20;
            int offset = 0;
            if(roomStr.Length > 0)
                length = length + 2 + roomStr.Length;
            byte[] userBuf = new byte[length];

            if(roomStr.Length > 0)
                userBuf[offset++] = 1;
            else
                userBuf[offset++] = 0;

            userBuf[offset++] = (byte)((account.Length & 0xFF00) >> 8);
            userBuf[offset++] = (byte)(account.Length & 0x00FF);

            byte[] accountByte = System.Text.Encoding.UTF8.GetBytes(account);
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

            if(roomStr.Length > 0)
            {
                userBuf[offset++] = (byte)((roomStr.Length & 0xFF00) >> 8);
                userBuf[offset++] = (byte)(roomStr.Length & 0x00FF);

                byte[] roomStrByte = System.Text.Encoding.UTF8.GetBytes(roomStr);
                roomStrByte.CopyTo(userBuf, offset);
                offset += roomStr.Length;
            }
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
    }
}
