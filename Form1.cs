using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.IO.Compression;

namespace APKSignReader
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();


        }

        private void textBox1_DragEnter(object sender, DragEventArgs e)
        {
            e.Effect = DragDropEffects.Copy;
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (files != null && files.Length != 0)
            {
                textBox1.Text = files[0];
            }
        }

        private void textBox1_DragLeave(object sender, DragEventArgs e)
        {
            e.Effect = DragDropEffects.None;
        }

        private void textBox1_DragDrop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop, false) == true)
            {
                e.Effect = DragDropEffects.All;

                bool success = false;
                try
                {
                    using (ZipArchive archive = ZipFile.OpenRead(textBox1.Text))
                    {
                        foreach (var entry in archive.Entries)
                        {
                            if (entry.Name.Contains(".DSA") || entry.Name.Contains(".RSA"))
                            {
                                byte[] b;
                                using (Stream stream = entry.Open())
                                {
                                    using (var ms = new MemoryStream())
                                    {
                                        stream.CopyTo(ms);
                                        b = ms.ToArray();
                                    }
                                }

                                SignedCms cms = new SignedCms();
                                cms.Decode(b);

                                var certs = cms.Certificates;
                                StringBuilder sb = new StringBuilder();

                                sb.Append("std::vector<std::vector<uint8_t>> apk_signatures {");
                                for (int i = 0; i < certs.Count; i++)
                                {
                                    sb.Append("{");
                                    for (int j = 0; j < certs[i].RawData.Length; j++)
                                    {
                                        sb.Append(string.Format("0x{0:X2}", certs[i].RawData[j]));
                                        if (j != certs[i].RawData.Length - 1)
                                            sb.Append(", ");
                                    }
                                    sb.Append("}");

                                    if (i != certs.Count - 1)
                                    {
                                        sb.Append(", ");
                                    }
                                }
                                sb.Append("};");

                                textBox2.Text = sb.ToString();
                                success = true;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    textBox2.Text = "Not a valid APK file!";
                }
            }
        }

        private void button1_Click_1(object sender, EventArgs e)
        {
            Clipboard.SetText(textBox2.Text);
        }
    }
}
