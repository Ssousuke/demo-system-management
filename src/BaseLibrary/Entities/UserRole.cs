namespace BaseLibrary.Entities
{
    public class UserRole
    {
        public int Id { get; set; }
        public int RoleId { get; set; }
        public Guid UserId { get; set; }
    }
}
