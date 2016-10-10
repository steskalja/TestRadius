
namespace System.Net.nRadius
{
    /****************************************************************************************
    * Class: RadiusAttribute                                                               *
    ****************************************************************************************
    * The class RadiusAttribute is contains ONE radius-attribute in an arraylist of bytes. *
    * There is also the need for an index for each Attribute, which is normally the        *
    * radius-Type                                                                          *
    ***************************************************************************************/

    /*
     * ATTRIBUTES (dynamic length):
     *  0                   1                   2
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
     * |      Type     |    Length     |  Value ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
     * 
     *  - User Password = Type 2 (String)
     *  A complete Attribute-List: http://www.freeradius.org/rfc/attributes.html
     */
    public class RadiusAttribute
    {
        //******************************ATTRIBUTES******************************************
        private byte pIndex = 0;
        private string pName = null;
        private byte[] pRadiusAttribute = null;
        private byte[] pPaket = null;
        //**********************************************************************************


        //******************************PROPERTIES******************************************
        public byte Index
        {
            get { return pIndex; }
        }

        public byte[] Attribute
        {
            set { pRadiusAttribute = value; }
            get { return pRadiusAttribute; }
        }

        public byte[] Paket
        {
            get { return pPaket; }
        }

        public string Name
        {
            get { return pName; }
        }

        //**********************************************************************************

        //******************************CONSTRUCTORS****************************************
        public RadiusAttribute()
        {
        } //public RadiusAttribute()

        public RadiusAttribute(byte Type, string Value)
        {
            Assemble_Attribute(Type, Value);
        } //public RadiusAttribute(byte Type, string Value)

        
        public RadiusAttribute(byte Type, byte[] Value)
        {
            Assemble_Attribute(Type, Value);
        } //public RadiusAttribute(byte Type, byte[] Value)
        //**********************************************************************************


        //*** METHODS ***

        /****************************************************************
         * private byte[] Assemble_Attribute(int Type, string Value)    *
         ****************************************************************
         * This Method assembles a radius Attribute                     *
         * The Input for the method is a string                         *
         ***************************************************************/
        public bool Assemble_Attribute(byte Type, string Value)
        {
            bool boResult = false;

            if (Type == 4 || Type == 8) //IP Addresses
            {
                try
                {
                    pRadiusAttribute = IPAddress.Parse(Value).GetAddressBytes();
                    byte[] pThisPaket = new byte[pRadiusAttribute.Length + 2];
                    pThisPaket[0] = Type; // The Type Field
                    pThisPaket[1] = Convert.ToByte(pThisPaket.Length);
                    Array.Copy(pRadiusAttribute, 0, pThisPaket, 2, pRadiusAttribute.Length);
                    pPaket = pThisPaket;
                    pIndex = Type;
                    pName = nRadius.Utils.TypeToString(Type);
                    boResult = true;
                }
                catch (Exception)
                {
                    pIndex = 0;
                    boResult = false;
                }
            } //if (Type == 4 || Type == 8)
            else
            {
                byte[] pThisPaket = new byte[Value.Length + 2];
                pThisPaket[0] = Type; // The Type Field
                pThisPaket[1] = Convert.ToByte(pThisPaket.Length);
                pRadiusAttribute = System.Text.Encoding.ASCII.GetBytes(Value);
                Array.Copy(pRadiusAttribute, 0, pThisPaket, 2, Value.Length);
                pPaket = pThisPaket;
                pIndex = Type;
                pName = nRadius.Utils.TypeToString(Type);
                boResult = true;
            }
            return boResult;
        } //private byte[] Assemble_Attribute(int Type, string Value) 

        
        
        /****************************************************************
         * private byte[] Assemble_Attribute(int Type, byte[] Value)    *
         ****************************************************************
         * This Method assembles a radius Attribute                     *
         * The Input for the method is a byte Array                     *
         ***************************************************************/
        private void Assemble_Attribute(byte Type, byte[] Value)
        {
            byte[] pThisPaket = new byte[Value.Length + 2];
            pThisPaket[0] = Type; // The Type Field
            pThisPaket[1] = Convert.ToByte(pThisPaket.Length);

            pRadiusAttribute = Value;
            Array.Copy(pRadiusAttribute, 0, pThisPaket, 2, Value.Length);

            pPaket = pThisPaket;
            pIndex = Type;
            pName = nRadius.Utils.TypeToString(Type);
        } //private byte[] Assemble_Attribute(int Type, string Value) 
              
    } //public class RadiusAttribute
}
