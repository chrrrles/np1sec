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


#include <assert.h>
#include <stdlib.h>
#include <string>

#include "src/session.h"
#include "src/exceptions.h"
#include "src/userstate.h"

using namespace std;
void MessageDigest::update(std::string new_message) {
  UNUSED(new_message);
  return;
}

static void cb_send_heartbeat(evutil_socket_t fd, short what, void *arg) {
  np1secSession* session = (static_cast<np1secSession*>(arg));
  session->send("Heartbeat", np1secMessage::PURE_META_MESSAGE);
  session->start_heartbeat_timer();
}

static void cb_ack_not_received(evutil_socket_t fd, short what, void *arg) {
  // Construct message for ack
  np1secSession* session = (static_cast<np1secSession*>(arg));
  session->send("Where is my ack?", np1secMessage::PURE_META_MESSAGE);
}

static void cb_send_ack(evutil_socket_t fd, short what, void *arg) {
  // Construct message with p.id
  np1secSession* session = (static_cast<np1secSession*>(arg));
  session->send("ACK", np1secMessage::PURE_META_MESSAGE);
}

np1secSession::np1secSession(np1secUserState *us)
  :myself(us->user_id())
{
  throw std::invalid_argument("Default constructor should not be used.");
}

/**
 * This constructor should be only called when the session is generated
 * to join. That's why all participant are not authenticated.
 */
np1secSession::np1secSession(np1secUserState *us, std::string room_name,
                             UnauthenticatedParticipantList participants_in_the_room) : us(us), room_name(room_name), participants_in_the_room(participants_in_the_room),   myself(us->user_id())
{
}

/**
   Constructor being called by current participant receiving join request
   That's why (in room) participants are are already authenticated
   
     - in new session constructor these will happen
       - computes session_id
       - compute kc = kc_{sender, joiner}
       - compute z_sender (self)
       - set new session status to REPLIED_TO_NEW_JOIN
       - send 
 */
np1secSession::np1secSession(std::string room_name, np1secMessage join_message, ParticipantMap current_authed_participants)
  :room_name(room_name) //TODO: not sure the session needs to know the room name
{
  my_state = DEAD; //in case anything fails
  
  this->participant = current_authed_participants;
   joiner = received_message.joiner_participant();
  //update participant info or let it be there if they are consistent with

  joiner_participant.insert(Participant(it->participant_id)); //the participant is added unauthenticated
  if (!participants[participant_id].set_ephemeral_key(it->ephemeral_key))
    throw np1secMessage::MessageFormatException;

  //We can't authenticate here, join message doesn't have kc
  // if (!participants[received_message.sender_id].authenticate(my_id, received_message.kc)) {
  //   return;
  // }

  compute_session_id();
  if (send_info_auth_and_share_message())
    my_state = REPLIED_TO_NEW_JOIN;

}

/**
   Constructor being called by current participant receiving leave request
   
     - in new session constructor these will happen
       - drop leaver
       - computes session_id
       - compute z_sender (self)
       - set new session status to RE_SHARED

*/
np1secSession::np1secSession(std::string room_name, string leaver_id, ParticipantMap current_authed_participants)
  :room_name(room_name) //TODO: not sure the session needs to know the room name
{
  my_state = DEAD; //in case anything fails

  participant = current_authed_participants;
  current_authed_participants.drop_participant(leaver_id);
  if (!participants[participant_id].set_ephemeral_key(it->ephemeral_key))
    throw np1secMessage::MessageFormatException;

  compute_session_id();
  if (send_share_message())
    my_state = RE_SHARED;

}

/**
 * it should be invoked only once to compute the session id
 * if one need session id then they need a new session
 *
 * @return return true upon successful computation
 */
bool np1secSession::compute_session_id() {
  std::string cat_string = "";
  //sanity check: You can only compute session id once
  assert(!session_id_set);

  if (peers.size() == 0) //nothing to compute
    return false;

  /**
   * Generate Session ID
   */

  //TODO:: Bill
  //session_id = Hash of (U1,ehpmeral1, U2);
  for (std::vector<std::string>::iterator it = peers.begin(); it != peers.end(); ++it) {
    Participant p = participants[*it];
    cat_string += p.id;
    cat_string += cryptic.retrieve_result(p.ephemeral_key);
  }

  compute_session_hash(session_id, cat_string);
  session_id_is_set = true;
  return true;

}

/**
 *  setup session view based on session view message,
 *  note the session view is set once and for all change in 
 *  session view always need new session object.
 */
bool np1secSession::setup_session_view(np1secMessage session_view_message) {

  //First get a list of user identities
  UnauthenticatedParticipantList plist =  received_message.participants_in_the_room();
  //update participant info or let it be there if they are consistent with

  assert(!session_id); //if session id isn't set we have to set it

  for(UnauthenticatedParticipantList::iterator it = plist.begin(); it != plist.begin(); it++) {
      //new participant we need to recompute the session id
    participants.insert(Participant(it->participant_id)); //the participant is added unauthenticated
    if (!participants[participant_id].set_ephemeral_key(it->ephemeral_key))
        throw np1secMessage::MessageFormatException;

  }

  compute_session_id();

}

bool np1secSessionState::everybody_authenticated_and_contributed()
{
  for(ParticipantMap::iterator it = participants.begin(); it != participants.end(); it++)
    if (!it->authenticated or !it->cur_keyshare)
      return false;

  return true;
  
}

bool np1secSessionState::everybody_confirmed()
{
  for(ParticipantMap::iterator it = confirmed.begin(); it != participants.end(); it++)
    if (!(*it))
      return false;

  return true;
  
}

/**
 *   Joiner call this after receiving the participant info to
 *    authenticate to everybody in the room
 */
bool np1secSessionState::joiner_send_auth_and_share() {
  assert(session_id_is_set);
  if (!group_enc()) //compute my share for group key
    return false;

  HashBlock cur_auth_token;

  std::string auth_batch; 

  for(uint32_t i = 0; i < peers.size(); i++) {
    if (!participants[peers[i]].authed_to) {
      participants[peers[i]].authenticate_to(cur_auth_token);
      auth_batch.append(reinterpret_cast<char*> &i, sizeof(uint32_t));
      auth_batch.append(cur_auth_token, sizeof(HashBlock));
    }
  }

  np1secMessage outboundmessage.create_participant_info(JOINER_AUTH,
                                                        sid,
                                                        "", //no unauthenticated_participant                                                                                  auth_batch,
                                                        session_key_share);
  outboundmessage.send();
  return true;

}
/**
   Preparinig PARTICIPANT_INFO Message

    current user calls this to send participant info to joiner
    and others
    sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
*/

bool np1secSessionState::send_view_auth_and_share(string joiner_id) {
  assert(session_id_is_set);
  if (!group_enc()) //compute my share for group key
    return false;

  HashBlock cur_auth_token;
  //    if (!participants[joiner_id].authed_to) {
  participants[joiner_id].authenticate_to(cur_auth_token);

  np1secMessage outboundmessage.create_participant_info(PARTICIPANT_INFO,
                                                        sid,
                                                        unauthenticated_participants,                                                                                  auth_token,
                                                        session_key_share);
  outboundmessage.send();
  return true;

}

/**
   Current user will use this to inform new user
   about their share and also the session plist klist

*/
bool np1secSessionState::send_share_message() {
  assert(session_id_is_set);
  if (!group_enc()) //compute my share for group key
    return false;
  
  np1secMessage outboundmessage.create_participant_info(RE_SHARE,
                                                        sid,
                                                        //unauthenticated_participants
                                                        //"",//auth_batch,
                                                        session_key_share);
  outboundmessage.send();
  return true;

}

/**
 * Receives the pre-processed message and based on the state
 * of the session decides what is the appropriate action
 *
 * @param receive_message pre-processed received message handed in by receive function
 *
 * @return true if state has been change 
 */
bool np1secSession::state_handler(np1secMessage receivd_message)
{
  switch(my_state) {
    case np1secSession::NONE:
      //This probably shouldn't happen, if a session has
      //no state state_handler shouldn't be called.
      //The receive_handler of the user_state should call
      //approperiate inition of a session of session less
      //message
      throw  np1secSessionStateException();
      break;
        
    case np1secSession::JOIN_REQUESTED: //The thread has requested to join by sending ephemeral key
      //Excepting to receive list of current participant
      break;
    case np1secSession::REPLIED_TO_NEW_JOIN: //The thread has received a join from a participant replied by participant list
      break;
    case np1secSession::GROUP_KEY_GENERATED: //The thread has computed the session key and has sent the conformation
      break;
    case np1secSession::IN_SESSION: //Key has been confirmed      
      break;
    case np1secSession::UPDATED_KEY: //all new shares has been received and new key has been generated: no more send possible
      break;
    case np1secSession::LEAVE_REQUESTED: //Leave requested by the thread: waiting for final transcirpt consitancy check
      break;
    case np1secSession::FAREWELLED: //LEAVE is received from another participant and a meta message for transcript consistancy and new shares has been sent
      break;
    case np1secSession::DEAD: //Won't accept receive or sent messages, possibly throw up
      break;
    default:
      return false;
  };
  
}

//***** Joiner state transitors ****

/**
   For join user calls this when receivemessage has type of PARTICIPANTS_INFO
   
   sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), (kc_{sender, joiner}), z_sender

   - Authenticate sender if fail halt

   for everybody including the sender

   joiner should:
   - set session view
   - compute session_id
   - add z_sender to the table of shares 
   - compute kc = kc_{joiner, everybody}
   - compute z_joiner
   - send 
   sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
*/
np1secSessionState np1secSession::auth_and_reshare(np1secMessage received_message) {
  if (!session_id_is_set) {
    if (!setup_session_view(received_message))
      return DEAD;
    send_auth_and_share_message();

  }

  if (!participants.find(received_message.sender_id))
    return DEAD;

  if (!participants[received_message.sender_id].authenticate(my_id, received_message.kc))
    return DEAD;

  participants[received_message.sender_id].set_key_share(received_message.z_share);

  return my_state;

  //TODO: check the ramification of lies by other participants about honest
  //participant ephemeral key. Normally nothing should happen as we recompute
  //the session id and so the session will never get messages from honest
  //participants and so will never be authed.

}

/**
   For the joiner user, calls it when receive a session confirmation
   message.
   
   sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), Hash(GroupKey, U_sender)
   
   of SESSION_CONFIRMATION type
   
   if it is the same sid as the session id, marks the confirmation in 
   the confirmation list for the sender. If all confirmed, change 
   state to IN_SESSION, call the call back join from ops.
   
   If the sid is different send a new join request
   
*/
np1secSessionState np1secSession::confirm_or_resession(np1secMessage received_message) {
  //if sid is the same mark the participant as confirmed
  //receiving mismatch sid basically means rejoin
  if (received_message.sid == session_id) {
    if (validate_session_confirmation())
      confirmed_peers[participant[received_message.sender_id].index] = true;
    else {
      my_state = DEAD;
      //as US to rejoin
      return;
    }

    if (everybody_confirmed())
      return IN_SESSION;
    
  }
  else {
    //we need to rejoin, categorically we are against chanigng session id
    //so we make a new session. This make us safely ignore replies to
    //old session id (they go to the dead session)
    np1secSession* new_child_session = new np1secSession(room_name); //calling join constructor;
    if (new_child_session->session_id_is_set) {
      new_child_session->my_parent = this;
      my_children[new_child_session->session_id] = new_child_session;
    }
    return DEAD;
    
  }

  return my_state;
  
}

//*****Joiner state transitors END*****

//*****Current participant state transitors*****
/**
     For the current user, calls it when receive JOIN_REQUEST with
     
     (U_joiner, y_joiner)

     - start a new new participant list which does
     
     - computes session_id
     - new session does:
     - compute kc = kc_{joiner, everybody}
     - compute z_sender (self)
     - set new session status to REPLIED_TO_NEW_JOIN
     - send

     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), (kc_{sender, joiner}), z_sender
     
     of PARTICIPANT_INFO message type

     change status to REPLIED_TO_NEW_JOIN

 */
np1secSessionState np1secSession::send_auth_share_and_participant_info(np1secMessage received_message)
{

  np1secSession* new_child_session = new np1secSession(received_message, participants);
  if (new_child_session->session_id_is_set) {
    new_child_session->my_parent = this;
    my_children[new_child_session->session_id] = new_child_session;
  }
  else //just throw the session out
    delete new_child_session;
    
  //our state doesn't need to change
  return my_state;

}

/**
   For the current user, calls it when receive JOINER_AUTH
   
   sid, U_sender, y_i, _kc, z_sender, signature

   or PARTICIPANT_INFO from users in the session
   
   - Authenticate joiner halt if fails
   - Change status to AUTHED_JOINER
   - Halt all sibling sessions
   
   - add z_sender to share table
   - if all share are there compute the group key send the confirmation
   
   sid, Hash(GroupKey, U_sender), signature 
   
   change status GROUP_KEY_GENERATED
   otherwise no change to the status
   
*/
np1secSessionState confirm_auth_add_update_share_repo(np1secMessage received_message) {
  if (received_message.type == np1secMessage::JOINER_AUTH) {
    if (!participants[received_message.sender_id].authenticate(my_id, received_message.kc))  {
        return DEAD;
      }

      kill_all_my_siblings(); 
      participants[received_message.sender_id].set_key_share(received_message.z_share);
  }
  else { //assuming the message is PARTICIPANT_INFO from other in
    //session people
    
  }

  if (everybody_authenticated_and_contributed) {
    if (group_dec()) {
      np1secMessage outboundmessage(SESSION_CONFIRMATION,
                                    sid,
                                    unauthenticated_participants,                                                           ""
                                    session_confirmation());
      outboundmessage.send();

      return GROUP_KEY_GENERATED;
    }

    return DEAD;
  }
  //otherwise just wait for more shares
  return my_state;
  
}

/**
   For the current user, calls it when receive a session confirmation
   message.
   
   sid, Hash(GroupKey, U_sender), signature
   
   if it is the same sid as the session id, marks the confirmation in 
   the confirmation list for the sender. If all confirmed, change 
   state to IN_SESSION, make this session the main session of the
   room
   
   If the sid is different, something is wrong halt drop session
   
*/
np1secSessionState np1secSession::mark_confirm_and_may_move_session(np1secMessage received_message) {
  //TODO:realistically we need to check sid, if sid
  //doesn't match we shouldn't have reached this point
  if (validate_session_confirmation())
    confirmed_peers[participant[received_message.sender_id].index] = true;
  else
    return DEAD;
  
  confirmed_peers[participant[received_message.sender_id].index] = true;
  
  if (everybody_confirmed()) {
    activate();
    return IN_SESSION;
  }

  return my_state;
    
}

/**
 * This will be called when another user leaves a chatroom to update the key.
 * 
 * This should send a message the same an empty meta message for sending
 * the leaving user the status of transcript consistency
 * 
 * This also make new session which send message of Of FAREWELL type new
 * share list for the shrinked session 
 *
 * sid, z_sender, transcript_consistency_stuff
 *
 * kills all sibling sessions in making as the leaving user is no longer 
 * available to confirm any new session.
 * 
 * The status of the session is changed to farewelled. 
 * The statatus of new sid session is changed to re_shared
 */
np1secSessionState np1secSession::send_farewell_and_reshare(np1secMessage received_message) {
  LoadFlag meta_load_flag = NO_LOAD;
  std::string meta_load = NULL;
  np1secMessage outbound(session_id, my_id,
                         FAREWELL,
                         group_enc()
                         transcript_chain_hash,
                         meta_load_flag,
                         meta_load,
                         peers, cryptic);


  np1secSession* new_child_session = new np1secSession(received_message, participants, leaver_id);
  
  if (new_child_session->session_id_is_set) {
    new_child_session->my_parent = this;
    my_children[new_child_session->session_id] = new_child_session;
  }
  else //just throw the session out
    delete new_child_session;
    
  //our state doesn't need to change
  return my_state;


}

bool np1secSession::join(LongTermIDKey long_term_id_key) {
  //We need to generate our ephemerals anyways
  if (!cryptic.init()) {
    return false;
  }
  myself.ephemeral_key = cryptic.get_ephemeral_pub_key();

  //we add ourselves to the (authenticated) participant list
  participants[myself.id];
  peers[0]=myself.id;

  // if nobody else is in the room have nothing to do more than
  // just computing the session_id
  if (participants_in_the_room.size()== 1) {
    assert(this->compute_session_id());
         
  }
  else {
    
  }
  us->ops->send_bare(room_name, us->user_id(), "testing 123", NULL);
  return true;
}

bool np1secSession::accept(std::string new_participant_id) {
  UNUSED(new_participant_id);
  return true;
}

bool np1secSession::received_p_list(std::string participant_list) {
  //Split up participant list and load it into the map
  char* tmp = strdup(participant_list.c_str());

  std::string ids_keys = strtok(tmp, ":03");
  std::vector<std::string> list_ids_keys;
  while (!ids_keys.empty()) {
    std::string decoded = "";
    otrl_base64_otr_decode(ids_keys.c_str(),
                           (unsigned char**)decoded.c_str(),
                           reinterpret_cast<size_t*>(ids_keys.size()));
    list_ids_keys.push_back(ids_keys);
    ids_keys = strtok(NULL, ":03");
  }

  for (std::vector<std::string>::iterator it = list_ids_keys.begin();
       it != list_ids_keys.end(); ++it) {
    tmp = strdup((*it).c_str());
    std::string id = strtok(tmp, ":03");
    std::string key = strtok(NULL, ":03");
    gcry_sexp_t sexp_key = cryptic.ConvertToSexp(key); 
    Participant p(id);
    p.ephemeral_key = sexp_key;
    unauthed_participants.insert(std::pair<std::string, Participant>(id, p));
  }

  return true;
}

bool np1secSession::farewell(std::string leaver_id) {
  UNUSED(leaver_id);
  return true;
}

void np1secSession::start_heartbeat_timer() {
  struct event *timer_event;
  struct timeval ten_seconds = {10, 0};
  struct event_base *base = event_base_new();

  timer_event = event_new(base, -1, EV_TIMEOUT, &cb_send_heartbeat, this);
  event_add(timer_event, &ten_seconds);

  event_base_dispatch(base);
}

void np1secSession::start_ack_timers() {
  struct event *timer_event;
  struct timeval ten_seconds = {10, 0};
  struct event_base *base = event_base_new();

  for (std::vector<std::string>::iterator it = peers.begin();
       it != peers.end();
       ++it) {
    timer_event = event_new(base, -1, EV_TIMEOUT, &cb_ack_not_received, this);
    awaiting_ack[*it] = timer_event;
    event_add(awaiting_ack[*it], &ten_seconds);
  }

  event_base_dispatch(base);
}

void np1secSession::start_receive_ack_timer(std::string sender_id) {
  struct event *timer_event;
  struct timeval ten_seconds = {10, 0};
  struct event_base *base = event_base_new();

  //msg = otrl_base64_otr_encode((unsigned char*)combined_content.c_str(),
  //                             combined_content.size());
  //(us->ops->send_bare)(room_name, myself.id, msg, static_cast<void*>(us));

  timer_event = event_new(base, -1, EV_TIMEOUT, &cb_send_ack, this);
  acks_to_send[sender_id] = timer_event;
  event_add(awaiting_ack[sender_id], &ten_seconds);
  event_base_dispatch(base);
}

void np1secSession::stop_timer_send() {
  for (std::map<std::string, struct event*>::iterator
       it = acks_to_send.begin();
       it != acks_to_send.end();
       ++it) {
    event_free(it->second);
    acks_to_send.erase(it);
  }
}

void np1secSession::stop_timer_receive(std::string acknowledger_id) {
  event_free(awaiting_ack[acknowledger_id]);
  awaiting_ack.erase(acknowledger_id);
}

void np1secSession::add_message_to_transcript(std::string message,
                                        uint32_t message_id) {
  HashBlock* hb;
  std::stringstream ss;
  std::string pointlessconversion;

  ss << transcript_chain.rbegin()->second;
  ss >> pointlessconversion;
  pointlessconversion += ":O3" + message;

  compute_message_hash(*hb, pointlessconversion);

  transcript_chain[message_id] = hb;
}

bool np1secSession::send(std::string message, np1secMessage::np1secMessageType message_type) {
  HashBlock* transcript_chain_hash = transcript_chain.rbegin()->second;
  // TODO(bill)
  // Add code to check message type and get
  // meta load if needed
  np1secLoadFlag meta_load_flag = NO_LOAD;
  std::string meta_load = NULL;
  np1secMessage outbound(session_id, us->user_id(),
                         message, message_type,
                         transcript_chain_hash,
                         meta_load_flag, meta_load,
                         peers, cryptic);

  // As we're sending a new message we are no longer required to ack
  // any received messages
  stop_timer_send();

  if (message_type == np1secMessage::USER_MESSAGE) {
    // We create a set of times for all other peers for acks we expect for
    // our sent message
    start_ack_timers();
  }

  // us->ops->send_bare(room_name, outbound);
  return true;
  
}

np1secMessage np1secSession::receive(std::string raw_message) {
  HashBlock* transcript_chain_hash = transcript_chain.rbegin()->second;
  np1secMessage received_message(raw_message, cryptic);

  if (*transcript_chain_hash == received_message.transcript_chain_hash) {
    add_message_to_transcript(received_message.user_message,
                        received_message.message_id);
    // Stop awaiting ack timer for the sender
    stop_timer_receive(received_message.sender_id);

    // Start an ack timer for us so we remember to say thank you
    // for the message
    start_receive_ack_timer(received_message.sender_id);

  } else {
    // The hash is a lie!
  }

  if (received_message.message_type == SESSION_P_LIST) {
    //TODO
    // function to separate peers
    // add peers to map
    // convert load to sexp
  }

  return received_message;
}

np1secSession::~np1secSession() {
  return;
}
