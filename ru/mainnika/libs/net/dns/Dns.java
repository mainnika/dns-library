package ru.mainnika.libs.net.dns;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Представление заголовка DNS пакета.
 *
 * @author MainNika
 */
public final class Dns {

    private byte[] raw;
    
    private boolean custom;
    
    private ArrayList<Dns.Query> queries;
    
    private ArrayList<Dns.Answer> answers;
    
    private ArrayList<Dns.Answer> authorities;
    
    private ArrayList<Dns.Answer> additionals;

    /**
     * Биты ID являются уникальным 16-битовым идентификационным номером пакета
     * запроса.
     */
    private short id;
    /**
     * Бит QR обозначает тип пакета.
     */
    private byte qr;
    /**
     * Поле OPCODE определяет тип запроса.
     */
    private byte opcode;
    /**
     * Бит AA устанавливается, когда ответ является авторитетным.
     */
    private byte aa;
    /**
     * Бит TC устанавливается, когда требуется урезать данные в пакете до вида,
     * удобного для передачи по сети.
     */
    private byte tc;
    /**
     * Бит RD включается, когда клиент желает рекурсивно запрашивать DNS-сервер
     * на постоянной основе.
     */
    private byte rd;
    /**
     * Бит RA устанавливается, чтобы уведомить клиента о возможности
     * рекурсивного запроса на данный сервер.
     */
    private byte ra;
    /**
     * Биты Z в настоящее время не используются и зарезервированы на будущее.
     */
    private byte z;
    /**
     * состояние ответа — без ошибок (0), ошибки в пакете запроса (1),
     * внутренние ошибки не дали возможности серверу обработать запрос (2), имя,
     * указанное в запросе, не существует (3), данный тип запроса не
     * поддерживается сервером (4) и сервер отказался обработать запрос (5).
     */
    private byte rcode;
    /**
     * QDCOUNT отображает количество запросов (в пакет может включаться более
     * одного запроса).
     */
    private short qdcount;
    /**
     * ANCOUNT — количество исходных записей, включенных в ответ.
     */
    private short ancount;
    /**
     * NSCOUNT обозначает число исходных записей об авторитетных серверах имен.
     */
    private short nscount;
    /**
     * ARCOUNT — число записей в поле дополнительной информации.
     */
    private short arcount;
    
    /* Конструктор кастомного пакета, создается отдельным методом, поэтому private */
    private Dns(byte[] raw){
        this.raw = raw;
        custom = true;
    }
    
    /* Конструктор стандартного пакета */
    public Dns(){
        queries = new ArrayList<>();
        answers = new ArrayList<>();
        authorities = new ArrayList<>();
        additionals = new ArrayList<>();
        custom = false;
    }
    
    /* Создание кастомного пакета из массива, пакет становится read-only */
    public static Dns mkCustomRawPacket(byte[] raw){
        return new Dns(raw);
    }

    /* Манипуляция с id */
    public short getId() {
        return id;
    }
    public Dns setId(short id) {
        this.id = id;
        return this;
    }
    
    public Dns genId() {
        Random rg = new Random();
        this.id = (short)rg.nextInt();
        return this;
    }

    /* Манипуляция с qr */
    public boolean issetQr() {
        return (qr == 0) ? false : true;
    }
    public Dns setQr() {
        qr = 1;
        return this;
    }
    public Dns unsetQr() {
        qr = 0;
        return this;
    }
    
    /* Манипуляция с opcode */
    public byte getOpcode() {
        return opcode;
    }
    public Dns setOpcode(byte opcode) {
        this.opcode = ((opcode < 16) && (opcode >= 0)) ? opcode : this.opcode;
        return this;
    }
    
    /* Манипуляция с aa */
    public boolean issetAa() {
        return (aa == 0) ? false : true;
    }
    public Dns setAa() {
        aa = 1;
        return this;
    }
    public Dns unsetAa() {
        aa = 0;
        return this;
    }

    /* Манипуляция с tc */
    public boolean issetTc() {
        return (tc == 0) ? false : true;
    }
    public Dns setTc() {
        tc = 1;
        return this;
    }
    public Dns unsetTc() {
        tc = 0;
        return this;
    }

    /* Манипуляция с rd */
    public boolean issetRd() {
        return (rd == 0) ? false : true;
    }
    public Dns setRd() {
        rd = 1;
        return this;
    }
    public Dns unsetRd() {
        rd = 0;
        return this;
    }

    /* Манипуляция с ra */
    public boolean issetRa() {
        return ra == 0 ? false : true;
    }
    public Dns setRa() {
        ra = 1;
        return this;
    }
    public Dns unsetRa() {
        ra = 0;
        return this;
    }

    /* Манипуляция с Z */
    public Dns setZ(byte z) {
        this.z = ((z >= 0) && (z < 8)) ? z : this.z;
        return this;
    }
    public byte getZ() {
        return z;
    }

    /* Манипуляция с rcode */
    public Dns setRcode(byte rcode) {
        this.rcode = ((rcode > -1) && (rcode < 16)) ? rcode : this.rcode;
        return this;
    }
    public short getRcode() {
        return rcode;
    }

    /* Получить qdcount */
    public short getQdcount() {
        return qdcount;
    }
    
    /* Получить ancount */
    public short getAncount() {
        return ancount;
    }

    /* Получить nscount */
    public short getNscount() {
        return nscount;
    }

    /* Получить arcount */
    public short getArcount() {
        return arcount;
    }    
    
    /* Добавить кастомный Query в пакет */
    public Dns addQuery(Dns.Query query){
        // TODO Check parent for query
        queries.add(query);
        qdcount++;
        return this;
    }
    
    /* Добавить стандартный Query в пакет */
    public Dns addQuery(String query, short qType, short qClass) throws DnsException{
        Dns.Query q = new Dns.Query();
        q.setQuery(query).setCl(qClass).setType(qType);
        queries.add(q);
        qdcount++;
        return this;
    }

    /* Получить Query по индексу */
    public Dns.Query getQueryAt(int index) throws DnsException{
        if (queries.size()<index){
            throw new DnsException("Only "+Integer.toString(queries.size())+" contains");
        }else{
            return queries.get(index);
        }
    }
    
    /* Получить размер блока Queries */
    public short getQueriesSize(){
        short ret=0;
        for (Dns.Query query : queries)
            ret+=query.getSize();
        return ret;
    }
    
    /* Добавление кастомного ответа в пакет */
    public Dns addAnswer(Dns.Answer answer){
        answers.add(answer);
        ancount++;
        return this;
    }
    
    // TODO public Dns addAnswer(Name name, short aType, short aClass, int aTtl, Name addData)
    
    public Answer getAnswerAt(int index) throws DnsException {
        if (answers.size()<index){
            throw new DnsException("Only "+Integer.toString(queries.size())+" contains");
        }else{
            return answers.get(index);
        }
    }
    
    // TODO public short getAnswersSize()

    // TODO public Dns addAuthority(Authority auth)
    
    // TODO public Dns addAuthority(Name name, short aClass, int aTtl, Name addData)
    
    // TODO public Authority getAuthorityAt(int index) throws DnsException
    
    // TODO public short getAuthoritySize()
    
    // TODO public Dns addAdditional(Additional auth)
    
    // TODO public Dns addAdditional(Name name, short aType, short aClass, int aTtl, Name addData)
    
    // TODO public Additional getAdditionalAt(int index) throws DnsException
    
    // TODO public short getAdditionalSize()
    
    /* Получение Name по смещению */
    public Dns.Data.Name getNameAtOffset(short offset) throws DnsException{
        
        if (offset<12)
            return null;//TODO Exception 
        
        if (offset<(getQueriesSize()+12))
            for (Dns.Query query : queries)
                for (Dns.Data.Name name : query.names)
                    if (offset==name.getOffset())
                        return name;
        
        
        return null;
        // TODO Add other datas;
    }
    
    public boolean containsName(Dns.Data.Name name){
        for (Dns.Query query : queries)
            if (query.names.contains(name))
                return true;
        
        // TODO add others;
        
        
        return false;
    }
    
    /* Вернет уже сформированный массив байт */
    public byte[] getRaw() throws Exception{
    
        if (custom)
            return raw.clone();
        
        ArrayList<byte[]> _raws = new ArrayList<>();
        int _size = 12;
        for (Dns.Query query: queries){
            byte[] newRaw = query.makeRaw();
            _size+=newRaw.length;
            _raws.add(newRaw);
        }
        for (Dns.Answer answer: answers){
            byte[] newRaw = answer.makeRaw();
            _size+=newRaw.length;
            _raws.add(newRaw);
        }
        for (Dns.Answer answer: authorities){
            byte[] newRaw = answer.makeRaw();
            _size+=newRaw.length;
            _raws.add(newRaw);
        }
        for (Dns.Answer answer: additionals){
            byte[] newRaw = answer.makeRaw();
            _size+=newRaw.length;
            _raws.add(newRaw);
        }     
        
        byte _raw[] = new byte[_size];
        _raw[0] = (byte) (id >> 8);
        _raw[1] = (byte) id;
        _raw[2] = (byte) ((qr << 7) | (opcode << 3) | (aa << 2) | (tc << 1) | rd);
        _raw[3] = (byte) ((ra << 7) | (z << 4) | rcode);
        _raw[4] = (byte) (qdcount >> 8);
        _raw[5] = (byte) qdcount;
        _raw[6] = (byte) (ancount >> 8);
        _raw[7] = (byte) ancount;
        _raw[8] = (byte) (nscount >> 8);
        _raw[9] = (byte) nscount;
        _raw[10] = (byte) (arcount >> 8);
        _raw[11] = (byte) arcount;
        _size = 12;
        
        for (byte[] _r : _raws){
            System.arraycopy(_r, 0, _raw, _size, _r.length);
            _size+=_r.length;
        }
        
        return _raw;
    }
        
    /* Формирует пакет из массива байт */
    public Dns fromRaw(byte[] raw) throws DnsException {
        
        try{
            id = (short) ((raw[0] << 8) | (0x00ff & raw[1]));
            qr = (byte) ((0x80 & raw[2]) >> 7);
            opcode = (byte) ((0x78 & raw[2]) >> 3);
            aa = (byte) ((0x4 & raw[2]) >> 2);
            tc = (byte) ((0x2 & raw[2]) >> 1);
            rd = (byte) (0x1 & raw[2]);
            ra = (byte) ((0x80 & raw[3]) >> 7);
            z = (byte) ((0x70 & raw[3]) >> 4);
            rcode = (byte) (0xf & raw[3]);
            qdcount = (short) ((raw[4] << 8) | (0x00ff & raw[5]));
            ancount = (short) ((raw[6] << 8) | (0x00ff & raw[7]));
            nscount = (short) ((raw[8] << 8) | (0x00ff & raw[9]));
            arcount = (short) ((raw[10] << 8) | (0x00ff & raw[11]));

            int lastoffset;
            int offset=12;

            for (int counter=0;counter<qdcount;counter++){
                lastoffset=offset;
                while (raw[offset]!=0)
                    offset+=raw[offset]+1;
                offset+=5;
                putQuery(new Dns.Query(Arrays.copyOfRange(raw, lastoffset, offset)));
            }
            
            for (int counter=0;counter<ancount;counter++){
                lastoffset=offset;
                while (raw[offset]!=0){
                    if ((0xc0 & raw[offset])==0xc0){
                        offset+=2;
                        break;
                    }else{
                        offset+=(int)raw[offset];
                    }
                }
                offset+=8;
                offset=offset+(int)((raw[offset]<<8) | raw[offset+1])+2;
                putAnswer(new Dns.Answer(Arrays.copyOfRange(raw, lastoffset, offset)));
            }
            
            for (int counter=0;counter<nscount;counter++){
                lastoffset=offset;
                while (raw[offset]!=0){
                    if ((0xc0 & raw[offset])==0xc0){
                        offset+=2;
                        break;
                    }else{
                        offset+=(int)raw[offset];
                    }
                }
                offset+=8;
                offset=offset+(int)((raw[offset]<<8) | raw[offset+1])+2;
                putAuthority(new Dns.Answer(Arrays.copyOfRange(raw, lastoffset, offset)));
            }
            
            for (int counter=0;counter<arcount;counter++){
                lastoffset=offset;
                while (raw[offset]!=0){
                    if ((0xc0 & raw[offset])==0xc0){
                        offset+=2;
                        break;
                    }else{
                        offset+=(int)raw[offset];
                    }
                }
                offset+=8;
                offset=offset+(int)((raw[offset]<<8) | raw[offset+1])+2;
                putAdditional(new Dns.Answer(Arrays.copyOfRange(raw, lastoffset, offset)));
            }
            
            
            
            custom = false;
            
            // TODO Add others
        }catch(Exception e){
            custom = true;
            throw new DnsException("Error while parsing packet: "+e.getMessage());
        }finally{
            this.raw = raw;
        }
        return this;
    }    
    
    /* Добавление Answer, использование только внутри класса, не инкрементирует ancount */
    private Dns putAnswer(Dns.Answer answer){
        answers.add(answer);
        return this;
    }
    
    private Dns putAdditional(Dns.Answer additional){
        answers.add(additional);
        return this;
    }
    
    private Dns putAuthority(Dns.Answer authory){
        answers.add(authory);
        return this;
    }
    
    
    /* Добавление Query, использование только внутри класса, не инкрементирует qdcount */
    private Dns putQuery(Dns.Query query){
        queries.add(query);
        return this;
    }    

    @Override
    public String toString() {
        String ret = "";
        for (Dns.Query query : queries){
            ret+=" QType:"+Integer.toString(query.getType())+":"+query;
        }
        for (Dns.Answer answer : answers){
            ret+=" AType:"+Integer.toString(answer.getType())+":"+answer;
        }
        
        return "ID:" + Integer.toString(id) + " QR:" + qr + " OP:" + opcode
                + " AA:" + aa + " TC:" + tc + " RD:" + rd + " RA:" + ra
                + " Z:" + Integer.toString(z) + " RC:" + Integer.toString(rcode)
                + " QD:" + Integer.toString(qdcount) + " AN:" + Integer.toString(ancount)
                + " NS:" + Integer.toString(nscount) + " AR:" + Integer.toString(arcount) + ret;
    }
    
    /* ———————————————————— Секция вложенных классов —————————————————————— */
    
    /* Стандартные функции для секций */
    public abstract class Data {
        abstract public byte[] makeRaw()  throws DnsException;
        abstract public short getOffset();
        abstract public short getNameOffset(Dns.Data.Name name) throws DnsException;
        abstract public int getNameCount();
        abstract public int getENameCount();
        abstract public boolean containsName(Dns.Data.Name name);
        abstract public short getDataType(); // 0 - domain part; 1 - IP; 2 - TXT; -1 - No data

        abstract protected void calcNames(ArrayList<Dns.Data.Name> buffer);
        abstract protected void calcENames(ArrayList<Dns.Data.Name> buffer);
        
        public Dns.Data.Name makeNameAsName(Dns.Data.Name name) throws DnsException {
            return new Dns.Data.Name(null,name,false);
        }
        public Dns.Data.Name makeNameAsName(String name) throws DnsException {
            return new Dns.Data.Name(name,null,false);
        }

        public Dns.Data.Name makeNameAsEName(Dns.Data.Name name) throws DnsException {
            return new Dns.Data.Name(null,name,true);
        }
        public Dns.Data.Name makeNameAsEName(String name) throws DnsException {
            return new Dns.Data.Name(name,null,true);
        }
        
        public class Name {

            /* Строковое представление имени */
            private String name;
            /* Сжатое представление имени, ссылка на полное */
            private Dns.Data.Name equivalent;       
            
            private boolean ename;

            private Name(String sname, Dns.Data.Name nname, boolean ename) throws DnsException {
                if (nname==null){
                    this.name = sname;
                    equivalent = null;
                    this.ename = ename;
                }else{
                    if ((Dns.Data.this.containsName(nname))||(!Dns.this.containsName(nname)))
                        throw new DnsException("Invalid name");
                    if ((nname.isEName())&&(nname.getDataType()!=0))
                        throw new DnsException("Invalid name");
                    name = null;
                    equivalent = nname;
                    this.ename = ename;
                }
            }
            
            
            
            public boolean isEName(){
                return ename;
            }
            
            public short getDataType(){
                return Dns.Data.this.getDataType();
            }
            
            public short getSize() {
                short ret;
                
                if (equivalent!=null){
                    ret = 2;
                }else{
                    if (ename){
                        switch(getDataType()){
                            case 1: ret = (short)4; break;
                            default: ret = (short)(name.length() + 1); 
                        }
                    }else{
                        ret = (short)(name.length() + 1);
                    }
                }
                
                return ret;
            }

            public short getOffset() throws DnsException{
                return Dns.Data.this.getNameOffset(this);
            }
            
            public Dns.Data.Name getThis() {
                return (equivalent == null) ? this : equivalent;
            }

            public String getName() {
                return (equivalent == null) ? name : equivalent.getName();
            }
            
            public int getCount(){
                if (ename){
                    return Dns.Data.this.getENameCount();
                }else{
                    return Dns.Data.this.getNameCount();
                }
            }
            
            public void pushNext(ArrayList<Dns.Data.Name> buffer){
                if (equivalent!=null){
                    equivalent.pushNext(buffer);
                }else{
                    Dns.Data.this.calcNames(buffer);
                }
            }
            
            public byte[] makeRaw() throws DnsException{
                byte[] quer = new byte[getSize()];
                if (!ename){
                    if (equivalent==null){
                        quer[0]=(byte)name.length();
                        byte[] rawname=name.getBytes();
                        System.arraycopy(rawname, 0, quer, 1, quer[0]);
                    }else{
                        int off = getThis().getOffset();
                        short tmp=(short) (49152 | off);
                        quer[1] = (byte)(tmp & 0xff);
                        quer[0] = (byte)((tmp >> 8) & 0xff);
                    }
                }else{
                    switch (getDataType()){ // 0 - domain part; 1 - IP; 2 - TXT; -1 - No data
                        case 1:{
                            String[] ip=name.split("\\."); 
                            for (int i=0; i<4; i++){
                                int tmp=Integer.parseInt(ip[i]);
                                quer[i]=(byte)tmp;
                            }
                        }
                        break;
                        default: {
                            if (equivalent == null) {
                                quer[0] = (byte) name.length();
                                byte[] rawname = name.getBytes();
                                System.arraycopy(rawname, 0, quer, 1, quer[0]);
                            } else {
                                short tmp = (short) (49152 | getOffset());
                                quer[0] = (byte) (tmp & 0xff);
                                quer[1] = (byte) ((tmp >> 8) & 0xff);
                            }
                        }
                    }
                            
                }
                return quer;
            }
            
            @Override
            public String toString() {
                return getName();
            }
        }
        
    }

    public class Query extends Dns.Data{
        
        private ArrayList<Dns.Data.Name> names;
        private short type;
        private short cl;

        @Override
        public byte[] makeRaw()  throws DnsException{
            int _size = 0;
            for (Dns.Data.Name name : names){
                _size+=name.getSize();
            }
            byte[] ret = new byte[_size+4];
            _size=0;
            for (int i=0; i<names.size();i++){
                byte[] _name = names.get(i).makeRaw();
                System.arraycopy(_name, 0, ret, _size, _name.length);
                _size+=_name.length;
                if ((names.get(i).equivalent==null)&&((i+1)==names.size())){
                    _size++;
                    ret = Arrays.copyOf(ret, ret.length+1);
                }
            }
            ret[ret.length-4] = (byte) (type >> 8);
            ret[ret.length-3] = (byte) type;
            ret[ret.length-2] = (byte) (cl >> 8);
            ret[ret.length-1] = (byte) cl;

            return ret;
        }
        
        
        
        public Dns.Answer makeAnwser() throws DnsException{
            Dns.Answer ret = new Dns.Answer();
            
            ret.addName(names.get(0));
            
            return ret;
        }

        private Query(byte[] raw) {
            
            names = new ArrayList<>();
            type=0;
            cl=0;
            
            short curroffset = 0;
            try {
                while (raw[curroffset] != 0) {
                    if ((raw[curroffset]&0xc0)==0xc0){
                        names.add(makeNameAsName(getNameAtOffset((short) ((raw[curroffset] << 8) | (0x00ff & raw[curroffset+1])))));
                        curroffset += 1;
                        break;
                    }else{
                        names.add(makeNameAsName(new String(Arrays.copyOfRange(raw, curroffset + 1, curroffset + 1 + raw[curroffset]))));
                        curroffset += raw[curroffset] + 1;
                    }
                }
                type = (short) ((raw[curroffset + 1] << 8) | (0x00ff & raw[curroffset + 2]));
                cl = (short) ((raw[curroffset + 3] << 8) | (0x00ff & raw[curroffset + 4]));
            } catch (Exception e) {
                names.clear();
                type=0;
                cl=0;
            }
        }
        
        public Query(){
            names = new ArrayList<>();
            type=0;
            cl=0;
        }
        
        public Dns.Query setQuery(String query) throws DnsException{
            names.clear();
            StringTokenizer st = new StringTokenizer(query, ".");
            while (st.hasMoreTokens()) {
                names.add(makeNameAsName(st.nextToken()));
            }
            return this;
        }
        
        public Dns.Query addName(String name) throws DnsException{
            names.add(makeNameAsName(name));
            return this;
        }
        
        public Dns.Query addName(Dns.Data.Name name) throws DnsException {
            names.add(makeNameAsName(name));
            return this;
        }
        
        @Override
        public int getNameCount(){
            int ret = names.size();
            if (names.get(names.size()-1).equivalent!=null){
                ret+=-1+names.get(names.size()-1).equivalent.getCount();
            }
            return ret;
        }

        @Override
        public int getENameCount() {
            return 0;
        }
        
        

        public ArrayList<Dns.Data.Name> getNames() {
            
            ArrayList<Dns.Data.Name> ret = new ArrayList<>(getNameCount());
            
            calcNames(ret);
            
            return ret;
        }
  

        @Override
        protected void calcNames(ArrayList<Dns.Data.Name> buffer) {
            for (int i=0; i<names.size()-1; i++)
                buffer.add(names.get(i));
            if (names.get(names.size()-1).equivalent!=null){
                names.get(names.size()-1).pushNext(buffer);
            }else{
                buffer.add(names.get(names.size()-1));
            }
            
        }
        
        @Override
        protected void calcENames(ArrayList<Dns.Data.Name> buffer) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        public Dns.Data.Name getNameAt(int index){
            return names.get(index);
        }

        public Dns.Query setCl(short cl) {
            this.cl = cl;
            return this;
        }

        public short getCl() {
            return cl;
        }

        public Dns.Query setType(short type) {
            this.type = type;
            return this;
        }

        public short getType() {
            return type;
        }
        
        public short getSize() {
            
            short ret=0;
            
            for (Dns.Data.Name name : names){
                ret+=name.getSize();
            }
            
            return (short)(ret+4);
        }
        
        @Override
        public String toString(){
            return names.toString();
            
        }
        
        @Override
        public short getOffset(){
            short ret = 12;
            for (int counter=0;counter<Dns.this.queries.indexOf(this);counter++){
                ret+=Dns.this.queries.get(counter).getSize();
            }
            return ret;
        }

        @Override
        public short getNameOffset(Dns.Data.Name name) {
            if (names.contains(name)){
                short ret=getOffset();
                for (int counter=0;counter<names.indexOf(name);counter++)
                    ret+=names.get(counter).getSize();
                return ret;
            }else{
                return -1;
            }
        }

        @Override
        public boolean containsName(Dns.Data.Name name) {
            return names.contains(name);
        }

        @Override
        public short getDataType() {
            return -1;
        }
    }

    public class Answer extends Dns.Data{
        
        private ArrayList<Dns.Data.Name> names;
        private short type;
        private short cl;
        private int ttl;
        private short dataType;
        private ArrayList<Dns.Data.Name> datas;
        
        private Answer(byte[] raw){
            names = new ArrayList<>();
            datas = new ArrayList<>();
            
            short curroffset = 0;
            try {
                while (raw[curroffset] != 0) {
                    if ((raw[curroffset]&0xc0)==0xc0){
                        names.add(makeNameAsName(getNameAtOffset((short) (((raw[curroffset] << 8) | (0x00ff & raw[curroffset+1])) & 0x3FFF))));
                        curroffset += 1;
                        break;
                    }else{
                        names.add(makeNameAsName(new String(Arrays.copyOfRange(raw, curroffset + 1, curroffset + 1 + raw[curroffset]))));
                        curroffset += raw[curroffset] + 1;
                    }
                }
                type = (short) ((raw[curroffset + 1] << 8) | (0x00ff & raw[curroffset + 2]));
                cl = (short) ((raw[curroffset + 3] << 8) | (0x00ff & raw[curroffset + 4]));
                curroffset+=9;
                // TODO ttl
                short dlen = (short)(curroffset + 1 + ((raw[curroffset] << 8) | (0x00ff & raw[curroffset + 1])));
                curroffset+=2;
                if (type==1){
                    byte[] __byte_ip = Arrays.copyOfRange(raw, curroffset, curroffset + 4);
                    String __string_ip = "";
                    for (int i = 0; i< __byte_ip.length; i++)
                        __string_ip+=Integer.toString(__byte_ip[i])+((i+1==__byte_ip.length)?"":".");
                    datas.add(makeNameAsEName(__string_ip));
                }else{
                    while (raw[curroffset] != 0) {
                        if ((raw[curroffset]&0xc0)==0xc0){
                            datas.add(makeNameAsEName(getNameAtOffset((short) (((raw[curroffset] << 8) | (0x00ff & raw[curroffset+1])) & 0x3FFF))));
                            curroffset += 1;
                            break;
                        }else{
                            datas.add(makeNameAsEName(new String(Arrays.copyOfRange(raw, curroffset + 1, curroffset + 1 + raw[curroffset]))));
                            curroffset += raw[curroffset] + 1;
                        }
                        if (curroffset > dlen) {
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                names.clear();
                datas.clear();
                type=0;
                cl=0;
            }
        }
        
        public Answer(){
            names = new ArrayList<>();
            datas = new ArrayList<>();
            type=0;
            cl=0;
            ttl=0;
        }

        @Override
        public byte[] makeRaw() throws DnsException{
            int _size = 0;
            short _dlen = 0;
            for (Dns.Data.Name name : names){
                _size+=name.getSize();
            }
            for (Dns.Data.Name name : datas){
                _size+=name.getSize();
                _dlen+=name.getSize();
            }
            byte[] ret = new byte[_size+10];
            _size=0;
            for (int i = 0; i< names.size(); i++){
                byte[] _name = names.get(i).makeRaw();
                System.arraycopy(_name, 0, ret, _size, _name.length);
                _size+=_name.length;
                if ((names.get(i).equivalent==null)&&(names.get(i).getDataType()==0)&&((i+1)==names.size())){
                    _size++;
                    ret = Arrays.copyOf(ret, ret.length+1);
                }
            }
            ret[_size++] = (byte) (type >> 8);
            ret[_size++] = (byte) type;
            ret[_size++] = (byte) (cl >> 8);
            ret[_size++] = (byte) cl;
            // TODO make raw ttl
            _size+=4;
            ret[_size++] = (byte) (_dlen >> 8);
            ret[_size++] = (byte) _dlen;
            for (Dns.Data.Name name : datas){
                byte[] _name = name.makeRaw();
                System.arraycopy(_name, 0, ret, _size, _name.length);
                _size+=_name.length;
            }
            return ret;
        }
        
        @Override
        public String toString(){
            return getENames().toString();
        }
        
        public Dns.Answer addName(String name) throws DnsException{
            names.add(makeNameAsName(name));
            return this;
        }
        
        public Dns.Answer addName(Dns.Data.Name name) throws DnsException{
            names.add(makeNameAsName(name));
            return this;
        }
        
        public Dns.Answer setDataAsIP(String ip) throws DnsException{
            dataType = 1;
            datas.clear();
            Pattern p = Pattern.compile("^[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*$");
            Matcher m = p.matcher(ip);
            if (m.matches()){
                datas.add(makeNameAsEName(ip));
            }
            
            /*
            StringTokenizer st = new StringTokenizer(ip,".");
            if (st.countTokens()!=4)
                throw new DnsException("Not ip");
            while (st.hasMoreTokens()){
                try{ // TODO REFACTORING ONLY
                    int hlop = Integer.parseInt(st.nextToken());
                    if ((hlop>=0)&&(hlop<256))
                        datas.add(makeNameAsEName(String.valueOf(hlop)));
                }catch (NumberFormatException nfe){
                    datas.clear();
                    throw new DnsException("Not ip");
                }
            }*/
            
            
            
            return this;             
        }
        
        public Dns.Answer setDataAsTXT(String txt) throws DnsException{
            dataType=2;
            datas.clear();
            datas.add(makeNameAsEName(txt));
            return this;
        }
        
        public Dns.Answer addDataAsURL(String url) throws DnsException{
            dataType=0;
            StringTokenizer st = new StringTokenizer(url,".");
            while (st.hasMoreTokens()){
                datas.add(makeNameAsEName(st.nextToken()));
            }        
            return this;
        }
        
        public Dns.Answer addDataAsURL(Dns.Data.Name name) throws DnsException{
            dataType=0;
            datas.add(name);
            return this;
        }
        
        public Dns.Answer setDataAsURL(String url) throws DnsException{
            datas.clear();
            return addDataAsURL(url);
        }
        
        @Override
        public short getDataType(){
            return dataType;
        }

        public void setType(short type) {
            this.type = type;
        }

        public short getType() {
            return type;
        }
        
        

        public void setCl(short cl) {
            this.cl = cl;
        }

        public short getCl() {
            return cl;
        }

        public void setTtl(int ttl) {
            this.ttl = ttl;
        }

        public int getTtl() {
            return ttl;
        }
        
        @Override
        public short getOffset() {
            
            short ret=12;
            
            for (int counter=0;counter<Dns.this.answers.indexOf(this);counter++){
                ret+=Dns.this.answers.get(counter).getSize();
            }
            
            return (short)(Dns.this.getQueriesSize()+ret);
        }

        @Override
        public boolean containsName(Dns.Data.Name name) {
            return ((names.contains(name))||(datas.contains(name)));
        }
        
        public short getSize(){
            short ret = 0;
            for(Dns.Data.Name name : names){
                ret+=name.getSize();
            }
            for(Dns.Data.Name name : datas){
                ret+=name.getSize();
            }
            return (short)(ret+10);
        }

        @Override
        public short getNameOffset(Dns.Data.Name name) throws DnsException{
            short ret=0;
            if (names.contains(name)){
                for (int i=0;i<names.indexOf(name);i++){
                    ret+=names.get(i).getSize();
                }
                return (short)(ret+getQueriesSize());
            } else if (datas.contains(name)){
                for (Dns.Data.Name cname : names){
                    ret+=cname.getSize();
                }
                for (int i=0;i<datas.indexOf(name);i++){
                    ret+=datas.get(i).getSize();
                }
                return (short)(ret+10);
            } else {
                throw new DnsException("not found");
            }
            
            //throw new DnsExc
        }
        
        public ArrayList<Dns.Data.Name> getNames() {
            
            int s = getNameCount();
            
            ArrayList<Dns.Data.Name> ret = new ArrayList<>(s);
            
            calcNames(ret);
            
            return ret;
        }

        @Override
        protected void calcNames(ArrayList<Dns.Data.Name> buffer) {
            for (int i=0; i<names.size()-1; i++)
                buffer.add(names.get(i));
            if (names.get(names.size()-1).equivalent!=null){
                names.get(names.size()-1).pushNext(buffer);
            }else{
                buffer.add(names.get(names.size()-1));
            }
            
        }

      
        public ArrayList<Dns.Data.Name> getENames() {
            
            ArrayList<Dns.Data.Name> ret = new ArrayList<>(getNameCount());
            
            calcENames(ret);
            
            return ret;
        }
        
        @Override
        protected void calcENames(ArrayList<Dns.Data.Name> buffer) {
            for (int i=0; i<datas.size()-1; i++)
                buffer.add(datas.get(i));
            if (datas.get(datas.size()-1).equivalent!=null){
                datas.get(datas.size()-1).pushNext(buffer);
            }else{
                buffer.add(datas.get(datas.size()-1));
            }
            
        }


        @Override
        public int getENameCount() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getNameCount(){
            int ret = names.size();
            if (names.get(names.size()-1).equivalent!=null){
                ret+=-1+names.get(names.size()-1).equivalent.getCount();
            }
            return ret;
        }
    }
}