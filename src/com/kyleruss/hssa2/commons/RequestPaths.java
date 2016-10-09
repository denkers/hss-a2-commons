//======================================
//  Kyle Russell
//  AUT University 2016
//  Highly Secured Systems A2
//======================================

package com.kyleruss.hssa2.commons;

public class RequestPaths 
{
    private RequestPaths() {}
    
    public static final String SERV_KEY_REQ     =   "/key/server/public/fetch";
    
    public static final String SERV_CONNECT_REQ =   "/user/connect";
    
    public static final String SERV_DISCON_REQ  =   "/user/disconnect";
    
    public static final String PASS_REQ         =   "/user/password/send";
    
    public static final String PUBLIC_SEND_REQ  =   "/key/user/add";
    
    public static final String USER_LIST_REQ    =   "/user/online/list";
    
    public static final String PUBLIC_GET_REQ   =   "/key/server/public/get";
    
    public static final String PROFILE_UP_REQ   =   "/user/profile/upload";
}
