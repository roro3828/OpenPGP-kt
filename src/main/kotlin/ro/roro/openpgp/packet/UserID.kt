package ro.roro.openpgp.packet

import java.io.ByteArrayInputStream
import java.io.DataInputStream

/**
 * ユーザーIDパケット
 */
class UserID:OpenPGPPacket {

    companion object{
        /**
         * バイト列からUserIDパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return UserID
         */
        fun fromBytes(body:ByteArray):UserID{
            val userid=body.decodeToString()

            return UserID(userid)
        }

        fun fromBytes(body: ByteArrayInputStream): UserID{
            val userid = body.readAllBytes().decodeToString()

            return UserID(userid)
        }

        fun fromBytes(body: DataInputStream): UserID{
            val userID = body.readAllBytes().decodeToString()

            return UserID(userID)
        }
    }

    /**
     * ユーザーID
     * 慣習的に "ユーザー名 <メールアドレス>"表記
     */
    val userID:String

    constructor(userID:String) {
        this.userID = userID
    }

    constructor(userName:String, mailAddress:String) {
        this.userID = String.format("%s <%s>",userName,mailAddress)
    }

    override val packetType: Int = OpenPGPPacket.USER_ID

    override val encoded: ByteArray
        get(){
            return userID.encodeToByteArray()
        }
    }