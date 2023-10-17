using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Web.WebView2.Wpf;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
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
        private TeslaAuthHelper teslaAuth;

        public MainWindow()
        {
            InitializeComponent();
        }

        private async void loginButton_Click(object sender, RoutedEventArgs e)
        {

            if (authModeCombo.SelectedIndex == 0)
            {
                teslaAuth = new TeslaAuthHelper("TeslaAuth/1.0");
            }
            else
            {
                var scopesToInclude = new List<string>();
                if (userDataCheckBox.IsChecked.Value) { scopesToInclude.Add(Scopes.UserData); }
                if (vehicleDataCheckBox.IsChecked.Value) { scopesToInclude.Add(Scopes.VechicleDeviceData); }
                if (vehicleCommandsCheckBox.IsChecked.Value) { scopesToInclude.Add(Scopes.VehicleCommands); }
                teslaAuth = new TeslaAuthHelper(TeslaAccountRegion.USA, clientIdTextBox.Text, clientSecretTextBox.Text, redirectUriTextBox.Text, Scopes.BuildScopeString(scopesToInclude.ToArray()));
            }

            await webView.EnsureCoreWebView2Async();
            webView.CoreWebView2.CookieManager.DeleteAllCookies();
            webView.Source = new Uri(teslaAuth.GetLoginUrlForBrowser());
            apiResponseTextBlock.Visibility = Visibility.Collapsed;
            webView.Visibility = Visibility.Visible;
        }


        private void webView_NavigationStarting(object sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationStartingEventArgs e)
        {
            var url = e.Uri.ToString();
            string redirectUri = String.IsNullOrEmpty(redirectUriTextBox.Text) ? "https://auth.tesla.com/void/callback" : redirectUriTextBox.Text;
            if (url.StartsWith(redirectUri))
            {
                webView.Visibility = Visibility.Hidden;
                Task.Run(async () =>
                {
                    var tokens = await teslaAuth.GetTokenAfterLoginAsync(url);
                    ShowTokens(tokens);
                }).ContinueWith(task =>
                {
                    if (task.IsFaulted)
                    {
                        Exception e = task.Exception;
                        if (e is AggregateException)
                            e = e.InnerException;
                        MessageBox.Show(e.Message, "Getting tokens after login failed");
                    }
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

        private void authModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (fleetAPIControls != null)
            {
                fleetAPIControls.Visibility = (authModeCombo.SelectedIndex == 0) ? Visibility.Collapsed : Visibility.Visible;
            }
            
        }

        private async void callApiButton_Click(object sender, RoutedEventArgs e)
        {
            string apiUrl;
            if (authModeCombo.SelectedIndex == 0)
            {
                apiUrl = "https://owner-api.teslamotors.com/api/1/products";
            }
            else
            {
                apiUrl = "https://fleet-api.prd.na.vn.cloud.tesla.com/api/1/me";
            }
            var client = new HttpClient();
            try
            {
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessTokenTextBox.Text);
                var request = new HttpRequestMessage(HttpMethod.Get, apiUrl);
                request.Headers.TryAddWithoutValidation("Content-Type", "application/json");
                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                apiResponseTextBlock.Text = await response.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                apiResponseTextBlock.Text = ex.ToString();
            }
            apiResponseTextBlock.Visibility = Visibility.Visible;   

        }
    }
}
