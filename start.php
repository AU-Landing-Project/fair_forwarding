<?php

/**
 * 	Fair Forwarding
 * 
 * 	gatekeeper and group_gatekeeper do a decent job of keeping track of the last
 *  page a user was unable to access if not logged in.  When logging in they redirect
 *  to that page.
 *  
 *  Some pages and plugins simply forward with no errors, and no redirect set which
 *  breaks user experience
 *  
 *  this plugin attempts to fix some of those instances
 */

function fair_forwarding_init(){
  
  // this only matters if we're not logged in
  if(!elgg_is_logged_in()){
    elgg_register_plugin_hook_handler('forward', 'all', 'fair_forwarding_forward_hook');
  }
}



/**
 * 	Hook on all forwards, try to determine if we're being shunted from something
 * 	we don't have access to
 */
function fair_forwarding_forward_hook($hook, $type, $returnvalue, $params){
  
  // only affect non-logged in users
  // the hook can be registered in non-default places using CAS or OpenID plugins
  if (elgg_is_logged_in()) {
    return $returnvalue;
  }
  
  // only affect internal urls
  if (strpos(current_page_url(), elgg_get_site_url()) === FALSE) {
    return $returnvalue;
  }
  
  
  $current_url = $params['current_url'];
  $forward_url = $returnvalue;
  
  // sent by gatekeepers - all ok
  if($type == 'login'){
    return $returnvalue;
  }
  
  // parse current url, if we find something like view/### or read/###
  // we can see if that is an entity guid we have access to
  // if not we can set our redirect url

  // get just the parts after the base url
  $current_url = str_ireplace(elgg_get_site_url(), "", $current_url);
  
  $parts = explode("/", $current_url);
  
  // remove empty array element when page url ends in a /
  if ($parts[count($parts) - 1] === '') {
    array_pop($parts);
  }
  
  // now do some testing
  // if we're being redirected from an action we don't want to do anything
  if($parts[0] == 'action'){
    return $returnvalue;
  }
  
  // strip get variables out of the last parameter - too many complications to parse those right now
  $lastpart = explode("?", $parts[count($parts)-1]);
  $parts[count($parts)-1] = $lastpart[0];
  
  // now iterate through the parts and look for anything that might be an entity guid
  // there may be more than one numerical value, eg. object, and container
  // so we'll assume that if we don't have access to one of them that's a permissions problem
  // eg. we can see the group, but not the page
  $set_last_forward_from = FALSE;
  foreach($parts as $part){
    if(is_numeric($part)){
      $entity = get_entity($part);
      if(!$entity){
        // we can't access an entity with this guid - set redirect url
        $_SESSION['last_forward_from'] = $params['current_url'];
        $set_last_forward_from = TRUE;
      }
    }
  }
  
  if($set_last_forward_from){
    if(count_messages() == 0){
      register_error(elgg_echo('fair_forwarding:redirected'));
    }
	return elgg_get_site_url() . 'login';
  }
}

elgg_register_event_handler('init', 'system', 'fair_forwarding_init');