using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using TeslaAuth;

namespace Test.WPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private TeslaAuthHelper teslaAuth = new TeslaAuthHelper("TeslaAuthSample/1.0");

        public MainWindow()
        {
            InitializeComponent();
        }

        private async void loginButton_Click(object sender, RoutedEventArgs e)
        {
            await webView.EnsureCoreWebView2Async();
            webView.CoreWebView2.CookieManager.DeleteAllCookies();
            webView.Source = new Uri(teslaAuth.GetLoginUrlForBrowser());
            webView.Visibility = Visibility.Visible;

        }

        private void webView_NavigationStarting(object sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationStartingEventArgs e)
        {
            var url = e.Uri.ToString();
            if (url.Contains("void/callback"))
            {
                webView.Visibility = Visibility.Hidden;
                Task.Run(async () =>
                {
                    var tokens = await teslaAuth.GetTokenAfterLoginAsync(url);
                    ShowTokens(tokens);
                });
            }
        }

        private async void refreshButton_Click(object sender, RoutedEventArgs e)
        {
            var refreshToken = refreshTokenTextBox.Text;
            if (!String.IsNullOrEmpty(refreshToken))
            {
                var newTokens = await teslaAuth.RefreshTokenAsync(refreshToken);
                ShowTokens(newTokens);
            }
        }

        private void ShowTokens(Tokens tokens)
        {
            // Update controls on UI thread
            Application.Current.Dispatcher.Invoke(new Action(() => {
                accessTokenTextBox.Text = tokens.AccessToken;
                refreshTokenTextBox.Text = tokens.RefreshToken;
                issuedTextBox.Text = tokens.CreatedAt.LocalDateTime.ToString();
                expiresTextBox.Text = tokens.ExpiresIn.ToString();
            }));
        }


    }
}
