using JWTAuth.Entities;
using System.Data.SqlClient;
using System.Threading.Tasks;

namespace JWTAuth.Data
{
    public class DataBaseHelper
    {
        private readonly string connectionString;

        public DataBaseHelper(IConfiguration configuration)
        {
            connectionString = configuration.GetConnectionString("DefaultConenction");
        }

        //To Register the User
        public bool AddUser(User user, out string errorMessage)
        {
            using (SqlConnection con = new SqlConnection(connectionString))
            {
                 con.Open();
                int count;
                string checkQuery = "Select count(*) from Users where Username = @Username";

                using (SqlCommand checkCmd = new SqlCommand(checkQuery, con))
                {
                    checkCmd.Parameters.AddWithValue("@Username", user.Username);
                    count = (int)checkCmd.ExecuteScalar();
                }
                if (count > 0)
                {
                    errorMessage = "Username Already exists";
                    return false;
                }
                else
                {
                    string query = "Insert Into Users (Id, Username, PasswordHash) Values (@Id, @Username, @PasswordHash)";

                    using (SqlCommand cmd = new SqlCommand(query, con))
                    {
                        cmd.Parameters.AddWithValue("@Id", user.Id);
                        cmd.Parameters.AddWithValue("@Username", user.Username);
                        cmd.Parameters.AddWithValue("@PasswordHash", user.PasswordHash);
                        int rowsAffected =  cmd.ExecuteNonQuery();
                        if (rowsAffected > 0)
                        {
                            errorMessage = null;
                            return true;
                        }
                        else
                        {
                            errorMessage = "Failed To Register the User.";
                            return false;
                        }
                    }
                }
            }
        }
        //TO check the username
        public User? GetUserNameByUsername(string username) {

            using (SqlConnection con = new SqlConnection(connectionString))
            {
                con.Open();
                string query = "Select Id, Username, PasswordHash From Users Where Username = @Username ";

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
                                PasswordHash = reader.GetString(2)
                            };
                        }
                    }
                }
            }
            return null;
        }

    }
}
