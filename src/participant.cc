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

#include <algorithm>

#include "src/participant.h"

namespace np1sec {

std::string participants_to_string(const ParticipantMap& plist)
{
  std::string string_plist;
  for(auto& cur_participant : plist)
    string_plist += ", " + cur_participant.first;

  string_plist.erase(0,2);

  return string_plist;
  
}

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool sort_by_long_term_pub_key(const PublicKey* lhs, const PublicKey* rhs)
{
  PublicKey* new_lhs = const_cast<PublicKey*>(lhs);
  PublicKey* new_rhs = const_cast<PublicKey*>(rhs);
  return public_key_to_stringbuff(new_lhs) < public_key_to_stringbuff(new_rhs);

}

/**
 * operator < needed by map class not clear why but it doesn't compile
 * It first does nick name check then public key check. in reality
 * public key check is not needed as the nickname are supposed to be 
 * unique (that is why nickname is more approperiate for sorting than
 * public key)
 */
bool operator<(const Participant& lhs, const Participant& rhs)
{
  if (lhs.id.nickname < rhs.id.nickname) return true;
  PublicKey lhs_wrapped(lhs.long_term_pub_key);
  PublicKey rhs_wrapped(rhs.long_term_pub_key);
  return sort_by_long_term_pub_key(&lhs_wrapped, &rhs_wrapped);
  
}
 
/**
 * Generate the approperiate authentication token check its equality
 * to authenticate the alleged participant
 *
 * @param auth_token authentication token received as a message
 * @param authenicator_id running thread user id  //TODO 
 *  can give it to youget rid of this as thread_user_as_partcipant 
 * @param thread_user_id_key the key (pub & prive) of the user running the 
 *        thread
 * 
 * @return true if peer's authenticity could be established
 */
void Participant::be_authenticated(const std::string authenticator_id, const HashBlock auth_token, const np1secAsymmetricKey thread_user_id_key, Cryptic* thread_user_crypto) {
  compute_p2p_private(thread_user_id_key, thread_user_crypto);

  std::string to_be_hashed(reinterpret_cast<const char*>(p2p_key), sizeof(HashBlock));
  to_be_hashed+= authenticator_id;
  HashBlock regenerated_auth_token;

  hash(to_be_hashed.c_str(), to_be_hashed.size(), regenerated_auth_token);

  if (compare_hash(regenerated_auth_token, auth_token)) {
      logger.warn("participant " + id.nickname + " failed TDH authentication");
      throw np1secAuthenticationException();
  } else {
    this->authenticated = true;
    
  }

  
 
}

/**
 * Generate the approperiate authentication token check its equality
 * to authenticate the alleged participant
 *
 * @param auth_token authentication token received as a message
 * @param thread_user_id_key the key (pub & prive) of the user running the 
 *        thread
 * 
 * @return true if peer's authenticity could be established
 */
void Participant::authenticate_to(HashBlock auth_token, const np1secAsymmetricKey thread_user_id_key, Cryptic* thread_user_crypto) {

  compute_p2p_private(thread_user_id_key, thread_user_crypto);

  std::string to_be_hashed(reinterpret_cast<const char*>(p2p_key), sizeof(HashBlock));
  to_be_hashed += id.id_to_stringbuffer(); //the question is that why should we include the public
  //key here?
  
  hash(to_be_hashed.c_str(), to_be_hashed.size(), auth_token);

}

/**
 * computes the p2p triple dh secret between participants
 *
 * @return true on success
 */
void Participant::compute_p2p_private(np1secAsymmetricKey thread_user_id_key, Cryptic* thread_user_crypto)
{
  // TODO - Make Participants use the new classes
  PublicKey ek_wrapped(ephemeral_key);
  PublicKey lt_wrapped(long_term_pub_key);
  AsymmetricKeyPair pair(thread_user_id_key);
  thread_user_crypto->triple_ed_dh(
    &ek_wrapped,
    &lt_wrapped,
    &pair,
    sort_by_long_term_pub_key(
      &lt_wrapped,
      pair.public_key),
    &p2p_key);
                      
}

/**
 *  this is basically the merge function
 */
ParticipantMap operator+(const ParticipantMap& lhs, const ParticipantMap& rhs)
{
  ParticipantMap result(lhs);

  result.insert(rhs.begin(), rhs.end());
  return result;
  
}

/**
 * this is basically the difference function
 */
ParticipantMap operator-(const ParticipantMap& lhs, const ParticipantMap& rhs)
{
  ParticipantMap difference;

  std::set_difference(
    lhs.begin(), lhs.end(),
    rhs.begin(), rhs.end(),
    std::inserter(difference, difference.end()));

  return difference;
  
}

} // namespace np1sec
