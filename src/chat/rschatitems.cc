
/*
 * libretroshare/src/serialiser: rsbaseitems.cc
 *
 * RetroShare Serialiser.
 *
 * Copyright 2007-2008 by Robert Fernie.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License Version 2 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 *
 * Please report all bugs and problems to "retroshare@lunamutt.com".
 *
 */

#include <stdexcept>
#include <time.h>
#include "serialiser/rsbaseserial.h"
#include "serialiser/rstlvbase.h"

#include "serialization/rstypeserializer.h"

#include "chat/rschatitems.h"

//#define CHAT_DEBUG 1

static const uint32_t RS_CHAT_SERIALIZER_FLAGS_NO_SIGNATURE = 0x0001;

RsItem *RsChatSerialiser::create_item(uint16_t service_id,uint8_t item_sub_id) const
{
    if(service_id != RS_SERVICE_TYPE_CHAT)
        return NULL ;

	switch(item_sub_id)
	{
        case RS_PKT_SUBTYPE_DEFAULT:				return new RsChatMsgItem() ;
		case RS_PKT_SUBTYPE_PRIVATECHATMSG_CONFIG:	return new RsPrivateChatMsgConfigItem() ;
        case RS_PKT_SUBTYPE_CHAT_STATUS:			return new RsChatStatusItem() ;
        case RS_PKT_SUBTYPE_CHAT_AVATAR:			return new RsChatAvatarItem() ;
		case RS_PKT_SUBTYPE_CHAT_LOBBY_SIGNED_MSG:	return new RsChatLobbyMsgItem() ;
        case RS_PKT_SUBTYPE_CHAT_LOBBY_INVITE:		return new RsChatLobbyInviteItem() ;
        case RS_PKT_SUBTYPE_CHAT_LOBBY_CHALLENGE:	return new RsChatLobbyConnectChallengeItem() ;
		case RS_PKT_SUBTYPE_CHAT_LOBBY_UNSUBSCRIBE:	return new RsChatLobbyUnsubscribeItem() ;
        case RS_PKT_SUBTYPE_CHAT_LOBBY_SIGNED_EVENT:return new RsChatLobbyEventItem() ;
		case RS_PKT_SUBTYPE_CHAT_LOBBY_LIST_REQUEST:return new RsChatLobbyListRequestItem() ;
		case RS_PKT_SUBTYPE_CHAT_LOBBY_LIST:        return new RsChatLobbyListItem() ;
        case RS_PKT_SUBTYPE_CHAT_LOBBY_CONFIG:  	return new RsChatLobbyConfigItem() ;
		default:
			std::cerr << "Unknown packet type in chat!" << std::endl ;
			return NULL ;
	}
}

void RsChatMsgItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::serial_process(j,ctx,chatFlags,"chatflags") ;
    RsTypeSerializer::serial_process(j,ctx,sendTime,"sendTime") ;
    RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_MSG,message,"message") ;
}

/*************************************************************************/

RsChatAvatarItem::~RsChatAvatarItem()
{
	if(image_data != NULL)
	{
		free(image_data) ;
		image_data = NULL ;
	}
}

void RsChatLobbyBouncingObject::serial_process(RsItem::SerializeJob j, SerializeContext& ctx)
{
    RsTypeSerializer::serial_process(j,ctx,lobby_id,"lobby_id") ;
    RsTypeSerializer::serial_process(j,ctx,msg_id  ,"msg_id") ;
    RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_NAME,nick,"nick") ;

    if(!(ctx.mFlags & RsServiceSerializer::SERIALIZATION_FLAG_SIGNATURE))
    	RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,signature,"signature") ;
}

void RsChatLobbyMsgItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsChatMsgItem::serial_process(j,ctx) ;
    RsTypeSerializer::serial_process(j,ctx,parent_msg_id,"parent_msg_id") ;
    RsChatLobbyBouncingObject::serial_process(j,ctx) ;
}

void RsChatLobbyListRequestItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    // nothing to do. This is an empty item.
}

template<> void RsTypeSerializer::serial_process(RsItem::SerializeJob j,SerializeContext& ctx,VisibleChatLobbyInfo& info,const std::string& name)
{
	RsTypeSerializer::serial_process<uint64_t>(j,ctx,info.id,"info.id") ;

	RsTypeSerializer::serial_process          (j,ctx,TLV_TYPE_STR_NAME,info.name, "info.name") ;
	RsTypeSerializer::serial_process          (j,ctx,TLV_TYPE_STR_NAME,info.topic,"info.topic") ;
	RsTypeSerializer::serial_process<uint32_t>(j,ctx,                  info.count,"info.count") ;
	RsTypeSerializer::serial_process          (j,ctx,                  info.flags,"info.flags") ;
}

void RsChatLobbyListItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::serial_process(j,ctx,lobbies,"lobbies") ;
}

void RsChatLobbyEventItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::serial_process<uint8_t>(j,ctx,event_type,"event_type") ;
    RsTypeSerializer::serial_process         (j,ctx,TLV_TYPE_STR_NAME,string1,"string1") ;
    RsTypeSerializer::serial_process<uint32_t>(j,ctx,sendTime ,"sendTime") ;

    RsChatLobbyBouncingObject::serial_process(j,ctx) ;
}
void RsChatLobbyUnsubscribeItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::serial_process<uint64_t>(j,ctx,lobby_id,"lobby_id") ;
}

void RsChatLobbyConnectChallengeItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::serial_process<uint64_t>(j,ctx,challenge_code,"challenge_code") ;
}

void RsChatLobbyInviteItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::serial_process<uint64_t>(j,ctx,                  lobby_id,   "lobby_id") ;
    RsTypeSerializer::serial_process          (j,ctx,TLV_TYPE_STR_NAME,lobby_name, "lobby_name") ;
    RsTypeSerializer::serial_process          (j,ctx,                  lobby_flags,"lobby_flags") ;
}

void RsPrivateChatMsgConfigItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    uint32_t x=0 ;

    RsTypeSerializer::serial_process<uint32_t>(j,ctx,                 x,           "place holder value") ;
    RsTypeSerializer::serial_process          (j,ctx,                 configPeerId,"configPeerId") ;
    RsTypeSerializer::serial_process<uint32_t>(j,ctx,                 chatFlags,   "chatFlags") ;
    RsTypeSerializer::serial_process<uint32_t>(j,ctx,                 sendTime,    "sendTime") ;
    RsTypeSerializer::serial_process          (j,ctx,TLV_TYPE_STR_MSG,message,     "message") ;
    RsTypeSerializer::serial_process<uint32_t>(j,ctx,                 recvTime,    "recvTime") ;
}

void RsChatStatusItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::serial_process(j,ctx,flags,"flags") ;
    RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_MSG,status_string,"status_string") ;
}

void RsChatAvatarItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::TlvMemBlock_proxy b(image_data,image_size) ;
    RsTypeSerializer::serial_process(j,ctx,b,"image data") ;
}

void RsChatLobbyConfigItem::serial_process(RsItem::SerializeJob j,SerializeContext& ctx)
{
    RsTypeSerializer::serial_process<uint64_t>(j,ctx,lobby_Id,"lobby_Id") ;
    RsTypeSerializer::serial_process(j,ctx,flags,"flags") ;
}

/* set data from RsChatMsgItem to RsPrivateChatMsgConfigItem */
void RsPrivateChatMsgConfigItem::set(RsChatMsgItem *ci, const RsPeerId& /*peerId*/, uint32_t confFlags)
{
	PeerId(ci->PeerId());
	configPeerId = ci->PeerId();
	chatFlags = ci->chatFlags;
	configFlags = confFlags;
	sendTime = ci->sendTime;
	message = ci->message;
	recvTime = ci->recvTime;
}

/* get data from RsPrivateChatMsgConfigItem to RsChatMsgItem */
void RsPrivateChatMsgConfigItem::get(RsChatMsgItem *ci)
{
	ci->PeerId(configPeerId);
	ci->chatFlags = chatFlags;
	//configFlags not used
	ci->sendTime = sendTime;
	ci->message = message;
	ci->recvTime = recvTime;
}


