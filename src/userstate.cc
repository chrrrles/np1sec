/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef SRC_USERSTATE_CC_
#define SRC_USERSTATE_CC_

#include <string>

#include "src/interface.h"
#include "src/userstate.h"

using namespace std;

np1secUserState::np1secUserState(std::string name, np1secAppOps *ops,
                                 uint8_t* key_pair) : name(name), ops(ops) {
  if (key_pair) {
    // FIXME: populate long_term_private_key from key_pair
  }
}

np1secUserState::~np1secUserState() {
  //TODO:Maybe for security reason we have
  //to turn long_term_key_pair into
  //pointer and fill-up mem before
  //deleting it
  //delete long_term_key_pair;
}

bool np1secUserState::init() {
  if (long_term_key_pair.is_initiated()) {
    return true;
  }
  return long_term_key_pair.generate();
}

bool np1secUserState::join_room(std::string room_name,
   UnauthenticatedParticipantList participants_in_the_room) {
  np1secSession *new_session = new np1secSession(this,
                                                 room_name,
                                                 participants_in_the_room);

  if (!new_session->join(long_term_key_pair)) {
    delete new_session;
    return false;
  }

  session_in_a_room.insert({ room_name, new_session });
  return true;
}

/**
   This is the main message handler of the whole protocol:

   The most important thing that user state message handler
   does is to 
       - Process the unencrypted part of the message.
       - decide which session should handle the message using
         the following procedure:
           1. If the message has sid:
                if there is a live session with that sid, deligate
                to that session
                else if the message has sid but session with such
                sid does not exists or the session is dead
                   if the room has active session, give it to the active sesssion of the room
                   else 
                      make a new session for that room and deligate it to it 
                      (but it is a sort of error, ignore the message. Join message doesn't have                    sid)

           2. If the message doesn't have sid, it is a join message
                if the room has active session
                  deligate it to the active session. 
                else
                  (this shouldn't happen either).
 */
RoomAction np1secUserState::receive_handler(std::string room_name,
                                            std::string np1sec_message,
                                            uint32_t message_id) {

  np1secMessage recieved = receive(received_message);
  np1secSession *cur_session = retrieve_session(room_name);
  if (!cur_session) {
    //only possible operation should be join and leave 
  if (np1sec_message.find(":o?JOIN:o?") == 0) {
    // check if it is ourselves or somebody else who is joining
    string joining_nick = np1sec_message.substr(strlen(":o?JOIN:o?"));

    if (name == joining_nick) {
      ;//ignore
    } else {
      this->accept_new_user(room_name, joining_nick);
    }
  } else if (np1sec_message.find(":o?LEAVE:o?") == 0) {
    string leaving_nick = np1sec_message.substr(strlen(":o?LEAVE:o?"));
    if (leaving_nick==name) {
      leave_room(room_name);
    } else {
      shrink_on_leave(room_name, leaving_nick);
    }
  } else if (np1sec_message.find(":o?SEND:o?") == 0) {
    string message_with_id = np1sec_message.substr(strlen(":o?SEND:o?"));
    size_t sender_pos = message_with_id.find(":o?");
    string message_id_str = message_with_id.substr(0, sender_pos);
    int message_id;
    stringstream(message_id_str) >> message_id;
    string sender_and_message = message_with_id.substr(
                                  sender_pos + strlen(":o?"));
    size_t message_pos = sender_and_message.find(":o?");
    string sender = message_with_id.substr(0, message_pos);
    // we don't care really about sender
    string pure_message = sender_and_message.substr(
                                    message_pos + strlen(":o?"));
  }
    
  }
  
  np1secMessage received_message = cur_session->receive(np1sec_message);
  RoomAction room_action = { NULL, received_message.user_message };
  return room_action;
}

bool np1secUserState::send_handler(std::string room_name,
                                   std::string plain_message) {
  np1secSession *cur_session = retrieve_session(room_name);
  if (!cur_session) {
    assert(false); 
    // uh oh
  }
  return cur_session->send(plain_message, np1secMessage::USER_MESSAGE);
}

np1secSession *np1secUserState::retrieve_session(std::string room_name) {
  np1secSession *cur_session = nullptr;
  session_room_map::iterator it = session_in_a_room.find(room_name);

  if ( it != session_in_a_room.end() ) {
    cur_session = it->second;
  }

  return cur_session;
}

#endif  // SRC_USERSTATE_CC_
