namespace BaseLibrary.Entities
{
    public class RefreshTokenInfo
    {
        public int Id { get; set; }
        public string? Token { get; set; }
        public Guid UserId { get; set; }
    }
}
