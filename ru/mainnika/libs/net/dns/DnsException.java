package ru.mainnika.libs.net.dns;

/**
 * 
 * @author MainNika
 */
public class DnsException extends Exception{
    public DnsException(String message){
        super(message);
    }
    public DnsException(){
        super();
    }
    // TODO Добавить идентификацию ошибочного пакета и получение по этому дополнительной информации.
}
