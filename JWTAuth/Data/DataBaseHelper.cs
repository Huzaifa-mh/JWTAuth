using JWTAuth.Entities;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Data.SqlClient;
using System.Threading.Tasks;

namespace JWTAuth.Data
{
    public class DataBaseHelper
    {
        private readonly string connectionString;
        //= "Server=DESKTOP-K6PE10I\\SQLEXPRESS;Database=MyDatabase;Trusted_Connection=True;TrustServerCertificate=True";

        public DataBaseHelper(IConfiguration configuration)
        {
            connectionString = configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Database connection string is missing."); ;
        }

        //To Register the User
        public async Task<(bool success, string? errorMessage)> AddUser(User user)
        {
            Console.WriteLine("Configuration: " + connectionString);
            using (SqlConnection con = new SqlConnection(connectionString))
            {
                ///async
                con.Open();
                int count;
                string checkQuery = "Select count(*) from Users where Username = @Username";

                using (SqlCommand checkCmd = new SqlCommand(checkQuery, con))
                {
                    checkCmd.Parameters.AddWithValue("@Username", user.Username);
                    count = (int)checkCmd.ExecuteScalar();
                }
                //this means that the ExecuteScaler will check the column mention in the query and if the given data exsists it will give 1
                if (count > 0)
                {
                    return (false, "Username Already Exists");
                }
                else
                {
                    string query = "Insert Into Users (Id, Username, PasswordHash, Role) Values (@Id, @Username, @PasswordHash, @Role)";

                    using (SqlCommand cmd = new SqlCommand(query, con))
                    {
                        cmd.Parameters.AddWithValue("@Id", user.Id);
                        cmd.Parameters.AddWithValue("@Username", user.Username);
                        cmd.Parameters.AddWithValue("@PasswordHash", user.PasswordHash);
                        cmd.Parameters.AddWithValue("@Role", user.Role);
                        int rowsAffected = cmd.ExecuteNonQuery();
                        if (rowsAffected > 0)
                        {
                            return (true, null);
                        }
                        else
                        {
                            return (false, "Failed To Register the User.");
                        }
                    }
                }
            }
        }
        //TO check the username
        public User? GetUserNameByUsername(string username)
        {

            using (SqlConnection con = new SqlConnection(connectionString))
            {
                con.Open();
                string query = "Select Id, Username, PasswordHash, Role From Users Where Username = @Username ";

                using (SqlCommand cmd = new SqlCommand(query, con))
                {
                    cmd.Parameters.AddWithValue("@Username", username);

                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return new User
                            {
                                Id = reader.GetGuid(0),
                                Username = reader.GetString(1),
                                PasswordHash = reader.GetString(2),
                                Role = reader.GetString(3)
                            };
                        }
                    }
                }
            }
            return null;
        }

        public bool  Delete(string name)
        {

            using (var con = new SqlConnection(connectionString))
            {
                con.Open();
                string query = "DELETE FROM Users Where Username = @Username";

                using (var cmd = new SqlCommand(query, con))
                {
                    cmd.Parameters.AddWithValue("@Username", name);
                    int rowAffected = cmd.ExecuteNonQuery();
                    if (rowAffected > 0)
                    {
                        return true;
                    }
                    else return false;
                }
            }
        }

    }
}
