fn normalize_user(name: &str, email: &str, active: bool) -> String {
    let clean_name = name.trim().to_lowercase();
    let clean_email = email.trim().to_lowercase();
    let enabled = active && !clean_email.is_empty();
    format!("{clean_name}:{clean_email}:{enabled}")
}
