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

#ifndef SRC_PARTICIPANT_H_
#define SRC_PARTICIPANT_H_

#include <string>
#include "src/crypt.h"

/** 
 * This class keeps the state of each participant in the room, including the
 * user themselves.
 */
class Participant {
 public:
  std::string id; //nickname;
  std::string nickname;
  LongTermPublicKey long_term_pub_key;
  np1secPublicKey ephemeral_key;
  HashBlock raw_ephemeral_key;
  // MessageDigest message_digest;

  np1secKeyShare cur_keyshare;
  HashBlock p2p_key = {};
  bool authenticated;
  bool authed_to;
  // np1secKeySHare future_key_share;

  uint32_t in_session_index; /* this is the i in U_i and we have
                                participants[peers[i]].index == i
                                tautology
                                
                                sorry we barely have space for half
                                half of human kind in a room :(
                             */

  enum ForwardSecracyContribution {
    NONE,
    EPHEMERAL,
    KEY_SHARE
  };

  ForwardSecracyContribution ForwardSecracyStatus = NONE;

  /**
   * crypto material access functions
   */
  bool set_ephmeral_key(HashBlock raw_ephemeral_key)
  {
    gcry_sexp_release(ephemeral_key);
    this->raw_ephemeral_key = raw_ephemeral_key;
    ephemeral_key = Cryptic::convert_to_sexp(it->ephemeral_key);

    return (ephemeral_key != NULL);
  }
  
  /**
   * default constructor
   */
 Participant(std::string participant_id = "")
   :id(participant_id),
    raw_ephemeral_key(NULL),
    ephemeral_key(NULL),
    authenticated(false),
    authed_to(false){
    
  }

};

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool sort_by_long_term_pub_key(Participant& lhs, Participant& rhs);

#endif  // SRC_PARTICIPANT_H_
